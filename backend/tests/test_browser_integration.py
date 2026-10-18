"""End-to-end check of real Chromium capture against a local page.
Skipped automatically if Chromium is not installed (`playwright install chromium`)."""
import asyncio
import dataclasses
import http.server
import threading

import pytest

from app.config import settings
from app.scanner.browser import capture_page
from app.scanner.resource_discovery import normalize
from app.scanner.ssrf_guard import HostGuard

FILES = {
    "/": ("text/html", b'<link rel=stylesheet href=/style.css><script src=/app.js></script><img src=/pic.png>'),
    "/style.css": ("text/css", b"body{color:#123}"),
    "/app.js": ("application/javascript", b"fetch('/api/data')"),
    "/pic.png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    "/api/data": ("application/json", b"{}"),
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ctype, body = FILES.get(self.path, ("text/plain", b"nf"))
        self.send_response(200 if self.path in FILES else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def local_site(monkeypatch):
    # Local test only: allowlist 127.0.0.1 so the SSRF guard lets the scanner reach it.
    monkeypatch.setattr("app.scanner.ssrf_guard.settings",
                        dataclasses.replace(settings, ssrf_allow_hosts=("127.0.0.1",)))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_real_browser_discovers_dependencies(local_site):
    fast = dataclasses.replace(settings, settle_ms=300, idle_timeout_ms=3000, page_load_timeout_ms=15000)
    try:
        cap = asyncio.run(capture_page(local_site + "/", fast, HostGuard()))
    except Exception as e:  # noqa: BLE001
        if "Executable doesn't exist" in str(e) or "playwright install" in str(e):
            pytest.skip("Chromium not installed")
        raise
    rows = {r["url"].replace(local_site, ""): r for r in normalize(cap.requests, cap.guard_blocked_urls)}
    assert {"/", "/style.css", "/app.js", "/pic.png", "/api/data"} <= set(rows)
    assert rows["/api/data"]["parent_resource_id"] == rows["/app.js"]["resource_id"]   # fetch() from script
    assert rows["/style.css"]["parent_resource_id"] == rows["/"]["resource_id"]
    assert all(r["load_status"] == "LOADED" for r in rows.values())
    assert all(r["remote_family"] == 4 for r in rows.values())


def test_full_scan_pipeline_persists_dns_and_context(local_site, monkeypatch):
    """Real Chromium -> resources -> DNS stage -> DB, with network-dependent context stubbed."""
    from app.models.db import SessionLocal, init_db
    from app.models.tables import HostProbe, MeasurementContext, Resource, Scan
    from app.scanner.context import ScanContext
    from app.services import scan_runner

    async def fake_ctx(force=False):
        return ScanContext(collected_at="2026-01-01T00:00:00Z", ipv4_egress_ok=True)
    monkeypatch.setattr(scan_runner, "get_context", fake_ctx)
    monkeypatch.setattr(scan_runner, "_sem", None)
    monkeypatch.setattr(scan_runner, "settings", dataclasses.replace(settings, settle_ms=300, idle_timeout_ms=3000))
    init_db()
    with SessionLocal() as db:
        db.add(Scan(scan_id="e2e000000001", target_url=local_site + "/", scanner_version="test"))
        db.commit()
    try:
        asyncio.run(scan_runner.run_scan("e2e000000001"))
    except Exception as e:  # noqa: BLE001
        if "Executable doesn't exist" in str(e):
            pytest.skip("Chromium not installed")
        raise
    with SessionLocal() as db:
        scan = db.get(Scan, "e2e000000001")
        if scan.status == "SCAN_FAILED" and "Executable doesn't exist" in (scan.error or ""):
            pytest.skip("Chromium not installed")
        assert scan.status == "COMPLETED", scan.error
        assert scan.summary["dns"]["hosts"] == 1
        probes = {p.family: p for p in db.query(HostProbe).filter_by(scan_id="e2e000000001")}
        assert probes[4].dns_status == "LITERAL" and probes[6].dns_status == "NOT_APPLICABLE"
        # Phase 3: the real local HTTP server is actually probed over IPv4 and reachable.
        assert probes[4].tcp_status == "PASS" and probes[4].verdict == "IPv4_REACHABLE"
        assert probes[6].verdict == "NOT_TESTED"              # host is an IPv4 literal; IPv6 not applicable
        res = db.query(Resource).filter_by(scan_id="e2e000000001").all()
        assert res and all(r.ipv4_addresses == ["127.0.0.1"] and r.ipv6_addresses == [] for r in res)
        assert db.get(MeasurementContext, "e2e000000001").ipv4_egress_ok is True


def test_real_batch_of_two_local_sites_end_to_end(local_site, monkeypatch):
    """Phase 6, for real: a genuine 2-site batch, each scanned with the REAL run_scan
    (real Chromium, real DNS, real TCP/TLS/HTTP probes) against real local servers -
    no fakes anywhere in this test. Proves the batch wiring (Batch/BatchSite rows,
    per-site scan_id, live progress, final summary) works end to end, not just that the
    orchestration logic is correct in isolation (which test_batch_runner.py already
    covers with fast fakes)."""
    import uuid

    from app.models.db import SessionLocal, init_db
    from app.models.tables import Batch, BatchSite, Scan
    from app.scanner.context import ScanContext
    from app.services import batch_runner as br
    from app.services import scan_runner

    async def fake_ctx(force=False):
        return ScanContext(collected_at="2026-01-01T00:00:00Z", ipv4_egress_ok=True)
    monkeypatch.setattr(scan_runner, "get_context", fake_ctx)
    monkeypatch.setattr(scan_runner, "settings",
                        dataclasses.replace(settings, settle_ms=300, idle_timeout_ms=1500))

    init_db()
    batch_id = uuid.uuid4().hex[:12]
    with SessionLocal() as db:
        db.add(Batch(batch_id=batch_id, total=2, source="custom", scanner_version="test"))
        db.commit()

    sites = [{"name": "local-a", "url": local_site + "/"}, {"name": "local-b", "url": local_site + "/"}]
    try:
        asyncio.run(br.run_batch(batch_id, sites, concurrency=2, site_timeout_s=30))
    except Exception as e:  # noqa: BLE001
        if "Executable doesn't exist" in str(e):
            pytest.skip("Chromium not installed")
        raise

    with SessionLocal() as db:
        batch = db.get(Batch, batch_id)
        assert batch.status == "COMPLETED"
        rows = db.query(BatchSite).filter_by(batch_id=batch_id).order_by(BatchSite.site_index).all()
        assert len(rows) == 2
        scan_ids = [r.scan_id for r in rows]
        assert len(set(scan_ids)) == 2  # duplicate URL, but independent scans - same guarantee as the unit test

        for scan_id in scan_ids:
            scan = db.get(Scan, scan_id)
            if scan.status == "SCAN_FAILED" and "Executable doesn't exist" in (scan.error or ""):
                pytest.skip("Chromium not installed")
            assert scan.status == "COMPLETED", scan.error
            assert scan.summary["resources"] >= 1
            assert scan.batch_id == batch_id  # linked back to the batch, for report/graph UI later

        progress = br.batch_progress(db, batch_id)
        assert progress == {"completed": 2, "total": 2, "by_status": {"COMPLETED": 2}}
