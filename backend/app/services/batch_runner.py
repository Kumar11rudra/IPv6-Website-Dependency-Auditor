"""30-site (or custom) batch scanning (PS-027 requirement 1/11).

Design rules, deliberately:
 * Reuses `scan_runner.run_scan` UNCHANGED for every site. SSRF validation and the
   DNS/TCP/TLS/HTTP failure classification are exactly what a single scan uses - a
   batch is not a separate code path that could silently diverge or be weakened.
 * Every site gets its own Scan row up front, before any scanning starts, so the
   planned site list is visible immediately (GET .../sites) and duplicate URLs never
   collide - each occurrence gets its own scan_id.
 * No shared, concurrently-mutated summary blob. Batch.status is written only by this
   single orchestrating coroutine; per-site status is always read live by joining to
   Scan, never cached, so concurrent site completions cannot race on a shared field.
 * One bad site (crash, hang, SSRF block) must never stop the rest of the batch.
"""
from __future__ import annotations
import asyncio
import json
import logging
import uuid
from collections import Counter
from pathlib import Path

from sqlalchemy import select

from ..config import settings
from ..models.db import SessionLocal
from ..models.tables import Batch, BatchSite, Scan, utcnow
from .scan_runner import run_scan

log = logging.getLogger(__name__)

TERMINAL = {"COMPLETED", "PARTIAL", "BLOCKED", "SCAN_FAILED"}


class SitesConfigError(ValueError):
    """sites.json is missing or malformed."""


def load_sites_config(path: str | None = None) -> list[dict]:
    p = Path(path or settings.sites_config_path)
    if not p.is_absolute():
        p = Path(__file__).resolve().parents[2] / p  # backend/
    try:
        data = json.loads(p.read_text())
    except FileNotFoundError:
        raise SitesConfigError(f"sites config not found: {p}")
    except json.JSONDecodeError as e:
        raise SitesConfigError(f"sites config is not valid JSON: {e}")
    if not isinstance(data, list) or not data:
        raise SitesConfigError("sites config must be a non-empty JSON array")
    for i, entry in enumerate(data):
        if not isinstance(entry, dict) or not entry.get("url"):
            raise SitesConfigError(f"sites config entry {i} is missing a 'url'")
    return [{"name": e.get("name") or e["url"], "url": e["url"]} for e in data]


def build_site_list(custom_sites: list[dict] | None, include_controlled: bool) -> tuple[list[dict], str]:
    """Returns (sites, source_label). Raises SitesConfigError / ValueError on bad input."""
    if custom_sites is not None:
        if not custom_sites:
            raise ValueError("custom site list is empty")
        for i, e in enumerate(custom_sites):
            if not isinstance(e, dict) or not e.get("url"):
                raise ValueError(f"custom site {i} is missing a 'url'")
        sites = [{"name": e.get("name") or e["url"], "url": e["url"]} for e in custom_sites]
        source = "custom"
    else:
        sites = list(load_sites_config())
        source = "default"

    if include_controlled and settings.controlled_site_url:
        sites = sites + [{"name": "Controlled Test Site (PS-027)", "url": settings.controlled_site_url}]

    if len(sites) > settings.batch_max_sites:
        raise ValueError(f"{len(sites)} sites exceeds the batch limit of {settings.batch_max_sites}")
    return sites, source


async def _run_one_site(scan_id: str, timeout_s: int, run_fn=None) -> None:
    """Runs the real scan for one site, bounded by a batch-level timeout so a single
    stuck site can never stall the whole batch. run_scan itself never raises and always
    leaves the Scan row in a terminal state - this wrapper only has to handle the case
    where run_scan doesn't finish in time, or raises for a reason even it didn't expect.
    `run_fn` is injectable (defaults to the real run_scan, looked up at CALL time, not
    bound into a default argument - so tests can monkeypatch module-level names and have
    it actually take effect) so tests can exercise this wrapper without a real browser."""
    run_fn = run_fn or run_scan
    try:
        await asyncio.wait_for(run_fn(scan_id), timeout_s)
    except asyncio.TimeoutError:
        _force_terminal(scan_id, "SCAN_FAILED", f"Batch site timeout exceeded ({timeout_s}s)")
    except Exception as e:  # noqa: BLE001 - one site's bug must never break the batch
        log.exception("batch site %s raised unexpectedly", scan_id)
        _force_terminal(scan_id, "SCAN_FAILED", f"Unexpected error: {type(e).__name__}: {e}"[:500])


def _force_terminal(scan_id: str, status: str, error: str) -> None:
    """Only overwrites if the scan is NOT already terminal, so a timeout that fires at
    the exact moment run_scan finishes can't clobber a real result with a false failure."""
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status in TERMINAL:
            return
        scan.status, scan.error, scan.finished_at = status, error, utcnow()
        db.commit()


async def run_batch(batch_id: str, sites: list[dict], *, concurrency: int | None = None,
                    site_timeout_s: int | None = None, scan_fn=None) -> None:
    concurrency = concurrency or settings.batch_concurrency
    site_timeout_s = site_timeout_s or settings.batch_site_timeout_s
    scan_fn = scan_fn or _run_one_site  # looked up at call time; see _run_one_site's docstring
    sem = asyncio.Semaphore(concurrency)

    with SessionLocal() as db:
        batch = db.get(Batch, batch_id)
        batch.status, batch.started_at = "RUNNING", utcnow()
        db.commit()

        scan_ids = []
        for i, site in enumerate(sites):
            scan_id = uuid.uuid4().hex[:12]
            db.add(Scan(scan_id=scan_id, target_url=site["url"], batch_id=batch_id,
                       scanner_version=settings.scanner_version))
            db.add(BatchSite(batch_id=batch_id, site_index=i, name=site["name"], url=site["url"], scan_id=scan_id))
            scan_ids.append(scan_id)
        db.commit()

    async def guarded(scan_id: str):
        async with sem:
            await scan_fn(scan_id, site_timeout_s)

    await asyncio.gather(*(guarded(sid) for sid in scan_ids), return_exceptions=True)

    with SessionLocal() as db:
        batch = db.get(Batch, batch_id)
        batch.status, batch.finished_at = "COMPLETED", utcnow()
        db.commit()


def batch_progress(db, batch_id: str) -> dict:
    """Computed fresh from the Scan table every time - never cached, so it's always
    consistent with whatever's actually happened, including mid-run."""
    statuses = db.scalars(
        select(Scan.status).join(BatchSite, BatchSite.scan_id == Scan.scan_id)
        .where(BatchSite.batch_id == batch_id)
    ).all()
    completed = sum(1 for s in statuses if s in TERMINAL)
    return {"completed": completed, "total": len(statuses), "by_status": dict(Counter(statuses))}
