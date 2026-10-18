"""Phase 6: the batch runner. Uses an injected fake scan_fn (matching the codebase's
established pattern - probe_fn, connect, http, etc.) so these are fast, deterministic
unit tests; a real end-to-end batch run against actual local servers is a separate test
in test_batch_integration.py."""
import asyncio
import json

import pytest

from app.models.db import SessionLocal, init_db
from app.models.tables import Batch, BatchSite, Scan
from app.services import batch_runner as br


@pytest.fixture(autouse=True)
def _db():
    init_db()


def make_batch(total: int, source: str = "custom") -> str:
    import uuid
    with SessionLocal() as db:
        b = Batch(batch_id=uuid.uuid4().hex[:12], total=total, source=source, scanner_version="t")
        db.add(b)
        db.commit()
        return b.batch_id


def sites(n: int, prefix: str = "site") -> list[dict]:
    return [{"name": f"{prefix}{i}", "url": f"https://{prefix}{i}.test/"} for i in range(n)]


def get_scan(scan_id: str) -> Scan:
    with SessionLocal() as db:
        return db.get(Scan, scan_id)


def batch_sites_rows(batch_id: str) -> list[BatchSite]:
    with SessionLocal() as db:
        return db.query(BatchSite).filter_by(batch_id=batch_id).order_by(BatchSite.site_index).all()


# --------------------------------------------------------------------------- basic batching
def test_every_site_gets_its_own_scan_row_up_front():
    async def instant_ok(scan_id, timeout_s):
        with SessionLocal() as db:
            s = db.get(Scan, scan_id)
            s.status = "COMPLETED"
            db.commit()

    batch_id = make_batch(3)
    asyncio.run(br.run_batch(batch_id, sites(3), scan_fn=instant_ok))

    rows = batch_sites_rows(batch_id)
    assert len(rows) == 3
    assert {r.url for r in rows} == {f"https://site{i}.test/" for i in range(3)}
    assert len({r.scan_id for r in rows}) == 3  # every site got a DISTINCT scan_id
    for r in rows:
        assert get_scan(r.scan_id).status == "COMPLETED"

    with SessionLocal() as db:
        assert db.get(Batch, batch_id).status == "COMPLETED"


def test_batch_progress_is_computed_live_not_cached():
    batch_id = make_batch(2)

    async def go():
        sem = asyncio.Semaphore(0)  # never released until the test lets it go

        async def blocks_until_released(scan_id, timeout_s):
            await sem.acquire()
            with SessionLocal() as db:
                db.get(Scan, scan_id).status = "COMPLETED"
                db.commit()

        task = asyncio.create_task(br.run_batch(batch_id, sites(2), scan_fn=blocks_until_released))
        await asyncio.sleep(0.05)
        with SessionLocal() as db:
            mid = br.batch_progress(db, batch_id)
        assert mid["completed"] == 0 and mid["total"] == 2  # still in flight
        sem.release(); sem.release()
        await task
        with SessionLocal() as db:
            final = br.batch_progress(db, batch_id)
        assert final["completed"] == 2

    asyncio.run(go())


# --------------------------------------------------------------------------- concurrency
def test_batch_respects_concurrency_limit():
    in_flight = 0
    max_seen = 0
    lock = asyncio.Lock()

    async def track(scan_id, timeout_s):
        nonlocal in_flight, max_seen
        async with lock:
            in_flight += 1
            max_seen = max(max_seen, in_flight)
        await asyncio.sleep(0.05)
        async with lock:
            in_flight -= 1
        with SessionLocal() as db:
            db.get(Scan, scan_id).status = "COMPLETED"
            db.commit()

    batch_id = make_batch(10)
    asyncio.run(br.run_batch(batch_id, sites(10), concurrency=3, scan_fn=track))
    assert max_seen <= 3
    assert max_seen > 1  # and it actually DID run concurrently, not serially


def test_batch_concurrency_of_one_is_fully_serial():
    order = []

    async def record(scan_id, timeout_s):
        order.append(("start", scan_id))
        await asyncio.sleep(0.01)
        order.append(("end", scan_id))
        with SessionLocal() as db:
            db.get(Scan, scan_id).status = "COMPLETED"
            db.commit()

    batch_id = make_batch(4)
    asyncio.run(br.run_batch(batch_id, sites(4), concurrency=1, scan_fn=record))
    # with concurrency=1, every start must be immediately followed by its own end
    for i in range(0, len(order), 2):
        assert order[i][0] == "start" and order[i + 1] == ("end", order[i][1])


# --------------------------------------------------------------------------- duplicate hosts
def test_duplicate_urls_produce_independent_scans_not_merged():
    async def instant_ok(scan_id, timeout_s):
        with SessionLocal() as db:
            db.get(Scan, scan_id).status = "COMPLETED"
            db.commit()

    dupe_sites = [{"name": "A", "url": "https://same.test/"}, {"name": "B", "url": "https://same.test/"},
                 {"name": "C", "url": "https://other.test/"}]
    batch_id = make_batch(3)
    asyncio.run(br.run_batch(batch_id, dupe_sites, scan_fn=instant_ok))

    rows = batch_sites_rows(batch_id)
    assert len(rows) == 3
    same_rows = [r for r in rows if r.url == "https://same.test/"]
    assert len(same_rows) == 2
    assert same_rows[0].scan_id != same_rows[1].scan_id  # distinct scans despite identical URL
    assert {r.name for r in same_rows} == {"A", "B"}      # neither entry silently overwrote the other


# --------------------------------------------------------------------------- timeout / partial failure
def test_one_stuck_site_times_out_without_blocking_the_batch():
    """Exercises the REAL _run_one_site timeout-wrapping logic (not run_batch's own
    gather), with only the innermost run_fn faked out."""
    async def hangs_forever(scan_id):
        await asyncio.sleep(10)  # much longer than the timeout given below

    async def finishes_fast(scan_id):
        with SessionLocal() as db:
            db.get(Scan, scan_id).status = "COMPLETED"
            db.commit()

    with SessionLocal() as db:
        db.add(Scan(scan_id="stuck0000001", target_url="https://stuck.test/", scanner_version="t"))
        db.add(Scan(scan_id="fine00000001", target_url="https://fine.test/", scanner_version="t"))
        db.commit()

    async def go():
        await asyncio.gather(
            br._run_one_site("stuck0000001", 0.1, run_fn=hangs_forever),
            br._run_one_site("fine00000001", 5, run_fn=finishes_fast),
        )
    asyncio.run(go())

    stuck, fine = get_scan("stuck0000001"), get_scan("fine00000001")
    assert stuck.status == "SCAN_FAILED" and "timeout" in stuck.error.lower()
    assert fine.status == "COMPLETED"  # the other site was NOT affected by the stuck one


def test_timeout_does_not_clobber_a_result_that_finished_just_in_time():
    """_force_terminal must never overwrite an already-terminal scan - guards the race
    where run_scan finishes right as the timeout fires."""
    with SessionLocal() as db:
        s = Scan(scan_id="race0000001", target_url="https://x.test/", scanner_version="t", status="COMPLETED")
        db.add(s)
        db.commit()
    br._force_terminal("race0000001", "SCAN_FAILED", "should not apply")
    assert get_scan("race0000001").status == "COMPLETED"


def test_run_one_site_wrapper_catches_unexpected_exceptions():
    """If the inner run function raises instead of timing out, the wrapper still leaves
    the scan in a terminal state rather than propagating and killing the batch."""
    async def crashes(scan_id):
        raise RuntimeError("boom")

    with SessionLocal() as db:
        db.add(Scan(scan_id="crash000001", target_url="https://x.test/", scanner_version="t"))
        db.commit()
    asyncio.run(br._run_one_site("crash000001", 5, run_fn=crashes))
    crashed = get_scan("crash000001")
    assert crashed.status == "SCAN_FAILED" and "boom" in crashed.error


def test_unexpected_exception_in_one_site_does_not_break_the_batch():
    """Full run_batch() level: one site's scan_fn raises; the rest of the batch and the
    batch itself must still complete. Uses the REAL _run_one_site wrapper (via a faked
    inner run_fn) as run_batch's scan_fn, so the exception-swallowing contract tested
    above is also proven to hold when driven through the full orchestrator."""
    async def flaky_by_url(scan_id, timeout_s):
        with SessionLocal() as db:
            url = db.get(Scan, scan_id).target_url

        async def inner(sid):
            if "boom" in url:
                raise RuntimeError("simulated crash")
            with SessionLocal() as db:
                db.get(Scan, sid).status = "COMPLETED"
                db.commit()

        await br._run_one_site(scan_id, timeout_s, run_fn=inner)

    crashy_sites = [{"name": "ok1", "url": "https://ok1.test/"}, {"name": "boom", "url": "https://boom.test/"},
                    {"name": "ok2", "url": "https://ok2.test/"}]
    batch_id = make_batch(3)
    asyncio.run(br.run_batch(batch_id, crashy_sites, scan_fn=flaky_by_url))

    with SessionLocal() as db:
        assert db.get(Batch, batch_id).status == "COMPLETED"  # batch still finished despite one crash
    rows = {r.name: r for r in batch_sites_rows(batch_id)}
    assert get_scan(rows["ok1"].scan_id).status == "COMPLETED"
    assert get_scan(rows["ok2"].scan_id).status == "COMPLETED"
    assert get_scan(rows["boom"].scan_id).status == "SCAN_FAILED"


# --------------------------------------------------------------------------- blocked targets
def test_blocked_target_among_others_does_not_stop_the_batch():
    """Uses the REAL run_scan (not a fake) for the blocked URL, so this is also a real
    proof that SSRF protection is untouched by the batch path: run_scan's own internal
    validate_target call is what produces BLOCKED here, exactly as in a single scan."""
    async def fake_run_fn_for_good_sites(scan_id):
        with SessionLocal() as db:
            db.get(Scan, scan_id).status = "COMPLETED"
            db.commit()

    async def scan_fn(scan_id, timeout_s):
        with SessionLocal() as db:
            url = db.get(Scan, scan_id).target_url
        if "169.254.169.254" in url:
            await br._run_one_site(scan_id, timeout_s)  # REAL run_scan -> real SSRF check
        else:
            await br._run_one_site(scan_id, timeout_s, run_fn=fake_run_fn_for_good_sites)

    mixed_sites = [{"name": "good1", "url": "https://good1.test/"},
                  {"name": "blocked", "url": "http://169.254.169.254/"},  # literal link-local IP: no DNS needed
                  {"name": "good2", "url": "https://good2.test/"}]
    batch_id = make_batch(3)
    asyncio.run(br.run_batch(batch_id, mixed_sites, scan_fn=scan_fn))

    with SessionLocal() as db:
        assert db.get(Batch, batch_id).status == "COMPLETED"
    rows = {r.name: r for r in batch_sites_rows(batch_id)}
    assert get_scan(rows["good1"].scan_id).status == "COMPLETED"
    assert get_scan(rows["good2"].scan_id).status == "COMPLETED"
    blocked = get_scan(rows["blocked"].scan_id)
    assert blocked.status == "BLOCKED" and blocked.error  # real SSRF guard fired, didn't hang/crash


# --------------------------------------------------------------------------- site-level summary
def test_summary_counts_every_status_bucket():
    async def scan_fn(scan_id, timeout_s):
        with SessionLocal() as db:
            url = db.get(Scan, scan_id).target_url
            scan = db.get(Scan, scan_id)
            if "fail" in url:
                scan.status = "SCAN_FAILED"
            elif "partial" in url:
                scan.status = "PARTIAL"
            elif "blocked" in url:
                scan.status = "BLOCKED"
            else:
                scan.status = "COMPLETED"
            db.commit()

    mixed = [{"name": "a", "url": "https://ok-a.test/"}, {"name": "b", "url": "https://ok-b.test/"},
             {"name": "c", "url": "https://willfail.test/"}, {"name": "d", "url": "https://partial.test/"},
             {"name": "e", "url": "https://blocked.test/"}]
    batch_id = make_batch(5)
    asyncio.run(br.run_batch(batch_id, mixed, scan_fn=scan_fn))

    with SessionLocal() as db:
        summary = br.batch_progress(db, batch_id)
    assert summary["total"] == 5 and summary["completed"] == 5  # all terminal
    assert summary["by_status"] == {"COMPLETED": 2, "SCAN_FAILED": 1, "PARTIAL": 1, "BLOCKED": 1}


def test_summary_mid_batch_shows_partial_completion():
    sites_mix = [{"name": "fast1", "url": "https://fast1.test/"}, {"name": "fast2", "url": "https://fast2.test/"},
                {"name": "slow", "url": "https://slow.test/"}]
    batch_id = make_batch(3)

    async def go():
        gate = asyncio.Event()

        async def scan_fn(scan_id, timeout_s):
            with SessionLocal() as db:
                url = db.get(Scan, scan_id).target_url
            if "slow" in url:
                await gate.wait()
            with SessionLocal() as db:
                db.get(Scan, scan_id).status = "COMPLETED"
                db.commit()

        task = asyncio.create_task(br.run_batch(batch_id, sites_mix, concurrency=3, scan_fn=scan_fn))
        await asyncio.sleep(0.1)
        with SessionLocal() as db:
            mid = br.batch_progress(db, batch_id)
        assert mid["completed"] == 2 and mid["by_status"].get("COMPLETED") == 2
        gate.set()
        await task
        with SessionLocal() as db:
            final = br.batch_progress(db, batch_id)
        assert final["completed"] == 3

    asyncio.run(go())
