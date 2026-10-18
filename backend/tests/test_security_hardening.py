"""Phase 9: security hardening regression tests.

Every test here corresponds to a specific finding recorded in docs/decisions.md's
Phase 9 section, classified there as FIXED / INTENTIONALLY MITIGATED / DOCUMENTED
LIMITATION. This file only covers FIXED findings (a fix without a test isn't really
fixed); the other two classifications are explained in the docs, not asserted here.
"""
import asyncio
import dataclasses
import http.server
import threading

import pytest

from app.config import settings
from app.scanner.browser import capture_page
from app.scanner.resource_discovery import normalize
from app.scanner.ssrf_guard import HostGuard, is_ip_blocked, normalize_ip_literal


# --------------------------------------------------------------------------------
# Flexible local HTTP server: each test supplies its own routing function, since the
# redirect/SSRF scenarios below need custom per-test behaviour, not a fixed file set.
# --------------------------------------------------------------------------------
def make_server(route_fn):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            route_fn(self)
        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def send_redirect(handler, location):
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.end_headers()


def send_ok(handler, body=b"<html>ok</html>", ctype="text/html"):
    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


@pytest.fixture
def allow_loopback(monkeypatch):
    monkeypatch.setattr("app.scanner.ssrf_guard.settings",
                        dataclasses.replace(settings, ssrf_allow_hosts=("127.0.0.1",)))


def fast_settings(**overrides):
    return dataclasses.replace(settings, settle_ms=300, idle_timeout_ms=1500,
                               ssrf_allow_hosts=("127.0.0.1",), **overrides)


def run_capture(url, cfg):
    try:
        return asyncio.run(capture_page(url, cfg, HostGuard()))
    except Exception as e:  # noqa: BLE001
        if "Executable doesn't exist" in str(e):
            pytest.skip("Chromium not installed")
        raise


# ================================================================================
# Finding 1: obscured IPv4 literal forms (decimal/octal/hex) bypassing the SSRF guard
# ================================================================================
class TestObscuredIPv4LiteralBypass:
    """CWE-918 class. Python's ipaddress.ip_address() rejects legacy BSD-style numeric
    forms (decimal whole-address, octal, hex, short forms) that Chromium's own WHATWG
    URL parser accepts and will connect to directly. Confirmed exploitable in principle
    (ipaddress rejects these forms) and then confirmed empirically that this project's
    actual resolution path happened to be safe only by accident (glibc's getaddrinfo
    implements the same permissive parsing) - fragile, not a guarantee. Fixed with an
    explicit, OS-independent normalize_ip_literal()."""

    @pytest.mark.parametrize("literal,expected", [
        ("2130706433", "127.0.0.1"),      # decimal whole-address
        ("0x7f000001", "127.0.0.1"),      # hex whole-address
        ("017700000001", "127.0.0.1"),    # octal whole-address
        ("127.1", "127.0.0.1"),           # short form (2 parts)
        ("0177.0.1", "127.0.0.1"),        # octal + short form combined
        ("3232235521", "192.168.0.1"),    # decimal form of a PRIVATE address
        ("2852039166", "169.254.169.254"),  # decimal form of the cloud metadata address
    ])
    def test_normalize_recognises_every_legacy_form(self, literal, expected):
        assert normalize_ip_literal(literal) == expected

    def test_normalize_still_rejects_real_hostnames(self):
        assert normalize_ip_literal("example.com") is None
        assert normalize_ip_literal("not-an-ip-at-all") is None

    def test_normalize_handles_ipv6_and_normal_ipv4_unchanged(self):
        assert normalize_ip_literal("127.0.0.1") == "127.0.0.1"
        assert normalize_ip_literal("2001:db8::1") == "2001:db8::1"
        assert normalize_ip_literal("8.8.8.8") == "8.8.8.8"

    @pytest.mark.parametrize("literal", ["2130706433", "0x7f000001", "017700000001", "127.1"])
    def test_obscured_loopback_forms_are_blocked(self, literal):
        assert is_ip_blocked(normalize_ip_literal(literal))

    def test_obscured_private_address_is_blocked(self):
        assert is_ip_blocked(normalize_ip_literal("3232235521"))  # decimal for 192.168.0.1

    def test_validate_target_rejects_every_obscured_form(self):
        from app.scanner.ssrf_guard import TargetRejected, validate_target
        for url in ("http://2130706433/", "http://0x7f000001/", "http://017700000001/", "http://127.1/"):
            with pytest.raises(TargetRejected):
                asyncio.run(validate_target(url))


# ================================================================================
# Finding 2: route()-based SSRF guard never sees (and so never blocks) redirect
# targets. Real browser tests - this is THE highest-severity finding in this audit,
# more reliable than DNS rebinding (needs no timing trick at all: any server the
# scanner visits can 302 straight to a private address). Fixed by replacing
# Playwright's route() with raw CDP Fetch-domain interception (see FetchInterceptor's
# docstring in scanner/browser.py for the full why).
# ================================================================================
class TestRedirectToPrivateAddressIsBlocked:
    def test_redirect_to_metadata_address_never_connects(self, allow_loopback):
        """The exact attack this finding is about: an ordinary public-looking resource
        302s straight to a classic SSRF target (cloud metadata address). Before the
        Phase 9 fix, this connected successfully - Playwright's route() never saw the
        redirect target at all. Confirmed exploitable, then confirmed fixed, both with
        a real browser."""
        def route(h):
            if h.path == "/":
                send_ok(h, b'<html><img src="/evil-redirect"></html>')
            elif h.path == "/evil-redirect":
                send_redirect(h, "http://169.254.169.254/latest/meta-data/")
            else:
                h.send_response(404); h.end_headers()

        srv = make_server(route)
        try:
            port = srv.server_address[1]
            cap = run_capture(f"http://127.0.0.1:{port}/", fast_settings())
            rows = normalize(cap.requests, cap.guard_blocked_urls, cap.redirect_limit_urls)
            metadata_rows = [r for r in rows if "169.254.169.254" in r["url"]]
            assert metadata_rows, "the redirect target should still be RECORDED (as blocked), not silently dropped"
            assert metadata_rows[0]["load_status"] == "BLOCKED"
            assert "SSRF guard" in metadata_rows[0]["error_text"]
            # the real guarantee: no row claims a successful connection to it
            assert not any(r["load_status"] == "LOADED" for r in metadata_rows)
        finally:
            srv.shutdown()

    def test_redirect_to_metadata_via_obscured_literal_is_blocked(self, allow_loopback):
        """Combines finding 1 and finding 2: a redirect to an OBSCURED-form private
        address must be caught by the SAME post-redirect interception. Uses
        169.254.169.254's decimal form (2852039166) rather than 127.0.0.1's: the test
        fixture allowlists "127.0.0.1" by hostname STRING so its own local test server
        is reachable, and Chromium normalises "2130706433" to the literal string
        "127.0.0.1" before CDP ever reports the URL to us (confirmed directly) - using
        127.0.0.1's decimal form here would therefore collide with the test's own
        allowlist and prove nothing. 169.254.169.254 is never allowlisted."""
        def route(h):
            if h.path == "/":
                send_ok(h, b'<html><img src="/go"></html>')
            elif h.path == "/go":
                send_redirect(h, "http://2852039166/internal")  # decimal for 169.254.169.254
            else:
                h.send_response(404); h.end_headers()

        srv = make_server(route)
        try:
            port = srv.server_address[1]
            cap = run_capture(f"http://127.0.0.1:{port}/", fast_settings())
            rows = normalize(cap.requests, cap.guard_blocked_urls, cap.redirect_limit_urls)
            # Chromium itself normalises the decimal literal to dotted-quad before CDP
            # reports the URL - confirmed directly; assert on the normalised form.
            target = [r for r in rows if "169.254.169.254" in r["url"]]
            assert target and target[0]["load_status"] == "BLOCKED"
            assert "SSRF guard" in target[0]["error_text"]
        finally:
            srv.shutdown()

    def test_multi_hop_redirect_where_only_the_last_hop_is_private(self, allow_loopback):
        """Several legitimate same-host hops, then a final hop to a private address -
        proves depth tracking doesn't somehow exempt a later hop from the SSRF check."""
        def route(h):
            if h.path == "/":
                send_redirect(h, "/hop1")
            elif h.path == "/hop1":
                send_redirect(h, "/hop2")
            elif h.path == "/hop2":
                send_redirect(h, "http://169.254.169.254/internal")
            else:
                h.send_response(404); h.end_headers()

        srv = make_server(route)
        try:
            port = srv.server_address[1]
            cap = run_capture(f"http://127.0.0.1:{port}/", fast_settings())
            rows = normalize(cap.requests, cap.guard_blocked_urls, cap.redirect_limit_urls)
            target = [r for r in rows if "169.254.169.254" in r["url"]]
            assert target and target[0]["load_status"] == "BLOCKED"
            assert not any("169.254.169.254" in r["url"] and r["load_status"] == "LOADED" for r in rows)
        finally:
            srv.shutdown()

    def test_ordinary_same_host_redirects_still_work_normally(self, allow_loopback):
        """Regression guard: the fix must not break completely normal redirects to
        public (here: allowlisted-local) destinations - the measurement methodology
        for legitimate pages must be unchanged."""
        def route(h):
            if h.path == "/":
                send_redirect(h, "/final")
            elif h.path == "/final":
                send_ok(h, b"<html>landed</html>")
            else:
                h.send_response(404); h.end_headers()

        srv = make_server(route)
        try:
            port = srv.server_address[1]
            cap = run_capture(f"http://127.0.0.1:{port}/", fast_settings())
            rows = normalize(cap.requests, cap.guard_blocked_urls, cap.redirect_limit_urls)
            final = [r for r in rows if r["url"].endswith("/final")]
            assert final and final[0]["load_status"] == "LOADED"
            assert not any(r["load_status"] == "BLOCKED" for r in rows)
        finally:
            srv.shutdown()


# ================================================================================
# Finding 3: no explicit, app-owned redirect-depth limit (relied entirely on
# Chromium's own internal ~20-hop limit, which this project does not control, cannot
# configure, and cannot verify). Fixed with an explicit, configurable, tested limit
# enforced in the SAME Fetch-domain interceptor as finding 2.
# ================================================================================
class TestRedirectDepthLimit:
    def test_chain_deeper_than_the_limit_is_blocked_before_completing(self, allow_loopback):
        hops = 25

        def route(h):
            n = int(h.path.strip("/") or "0")
            if n < hops:
                send_redirect(h, f"/{n + 1}")
            else:
                send_ok(h, b"<html>should never be reached</html>")

        srv = make_server(route)
        try:
            port = srv.server_address[1]
            cfg = fast_settings(max_redirects_per_chain=15)
            cap = run_capture(f"http://127.0.0.1:{port}/0", cfg)
            assert len(cap.redirect_limit_urls) == 1
            rows = normalize(cap.requests, cap.guard_blocked_urls, cap.redirect_limit_urls)
            assert not any(r["load_status"] == "LOADED" and f"/{hops}" in r["url"] for r in rows)
            blocked = [r for r in rows if r["load_status"] == "BLOCKED"]
            assert blocked and "redirect chain exceeded" in blocked[0]["error_text"]
        finally:
            srv.shutdown()

    def test_chain_within_the_limit_completes_normally(self, allow_loopback):
        hops = 5

        def route(h):
            n = int(h.path.strip("/") or "0")
            if n < hops:
                send_redirect(h, f"/{n + 1}")
            else:
                send_ok(h, b"<html>reached</html>")

        srv = make_server(route)
        try:
            port = srv.server_address[1]
            cfg = fast_settings(max_redirects_per_chain=15)
            cap = run_capture(f"http://127.0.0.1:{port}/0", cfg)
            assert len(cap.redirect_limit_urls) == 0
            rows = normalize(cap.requests, cap.guard_blocked_urls, cap.redirect_limit_urls)
            assert any(r["url"].endswith(f"/{hops}") and r["load_status"] == "LOADED" for r in rows)
        finally:
            srv.shutdown()


# ================================================================================
# Finding 4: Phase 7's redaction was wired into the /report/* endpoints only. Every
# other live, client-facing endpoint (the ones the dashboard actually polls and
# displays) returned raw, unredacted url/error fields - a credential or token embedded
# in a discovered resource's URL was fully visible in the live UI even though already
# hidden from exported reports. Fixed by applying the SAME redact_url/redact_text
# functions at the Pydantic serialization layer for every live endpoint too.
# ================================================================================
class TestLiveEndpointRedaction:
    def _seed(self, scan_id, target_url="https://x.test/", resource_url=None, error=None):
        from app.models.db import SessionLocal
        from app.models.tables import HostProbe, Resource, Scan
        with SessionLocal() as db:
            db.add(Scan(scan_id=scan_id, target_url=target_url, status="COMPLETED",
                       scanner_version="t", error=error))
            if resource_url:
                db.add(Resource(scan_id=scan_id, resource_id="r1", parent_resource_id=None,
                                parent_inferred=False, url=resource_url, hostname="x.test", port=443,
                                scheme="https", resource_type="script", initiator="root",
                                load_status="LOADED", http_status=200))
                db.add(HostProbe(scan_id=scan_id, hostname="x.test", port=443, family=6,
                                 dns_status="OK", verdict="IPv6_REACHABLE",
                                 error_detail=f"probe note for {resource_url}" if resource_url else None))
            db.commit()

    def test_scan_endpoint_redacts_target_and_final_url(self, client):
        self._seed("secliv0000a1", target_url="https://user:hunter2@x.test/")
        body = client.get("/api/scan/secliv0000a1").json()
        assert "hunter2" not in str(body)

    def test_resources_endpoint_redacts_url(self, client):
        self._seed("secliv0000b1", resource_url="https://x.test/x.js?token=LIVETOK123")
        r = client.get("/api/scan/secliv0000b1/resources")
        assert "LIVETOK123" not in r.text

    def test_graph_endpoint_redacts_resource_urls(self, client):
        self._seed("secliv0000c1", resource_url="https://x.test/x.js?secret=GRAPHSECRET1")
        r = client.get("/api/scan/secliv0000c1/graph")
        assert "GRAPHSECRET1" not in r.text

    def test_probes_endpoint_redacts_error_detail(self, client):
        self._seed("secliv0000d1", resource_url="https://x.test/x.js?apikey=PROBESECRET1")
        r = client.get("/api/scan/secliv0000d1/probes")
        assert "PROBESECRET1" not in r.text

    def test_batch_sites_endpoint_redacts_site_url(self, client):
        from app.models.db import SessionLocal
        from app.models.tables import Batch, BatchSite, Scan
        with SessionLocal() as db:
            db.add(Batch(batch_id="secbatch0001", total=1, source="custom", scanner_version="t"))
            db.add(Scan(scan_id="secbatchscan1", target_url="https://x.test/", status="COMPLETED",
                       scanner_version="t"))
            db.add(BatchSite(batch_id="secbatch0001", site_index=0, name="x",
                             url="https://user:batchsecret@x.test/", scan_id="secbatchscan1"))
            db.commit()
        r = client.get("/api/batch-scan/secbatch0001/sites")
        assert "batchsecret" not in r.text

    def test_non_sensitive_data_is_not_corrupted_by_the_redaction_layer(self, client):
        """Regression guard: redaction must not mangle ordinary, non-sensitive URLs -
        only secrets get touched."""
        self._seed("secliv0000e1", resource_url="https://x.test/app.js?version=2&page=1")
        r = client.get("/api/scan/secliv0000e1/resources").json()
        assert r[0]["url"] == "https://x.test/app.js?version=2&page=1"

    def test_redact_text_catches_secrets_in_embedded_urls_not_just_header_patterns(self):
        """redact_text's docstring claims 'defense in depth' for ANY free text - this
        proves that claim is true for the most obvious case (a URL pasted into a
        message), not just the Authorization/Cookie/Bearer patterns it started with."""
        from app.reports.redact import redact_text
        out = redact_text("probe note for https://x.test/x.js?apikey=HIDDENSECRET1")
        assert "HIDDENSECRET1" not in out
        # non-sensitive embedded URLs and surrounding prose are left alone
        assert redact_text("see https://x.test/page for details") == "see https://x.test/page for details"


# ================================================================================
# Finding 5: CSV/formula injection (CWE-1236). RFC-4180 escaping protects the CSV's
# STRUCTURE but says nothing about how Excel/Sheets interprets a cell once a human
# opens it - a resource URL or error message starting with =, +, -, or @ could be
# read as a formula. Every field in this report comes from a page the scanner
# visited, never from a source this application controls, so this is a real surface.
# Fixed with the standard OWASP mitigation: prefix a leading single quote.
# ================================================================================
class TestCsvFormulaInjection:
    def test_dangerous_leading_characters_are_neutralised(self):
        from app.reports.csv_report import sanitize_csv_field
        for dangerous in ('=HYPERLINK("http://evil.com","click")', "+cmd|' /C calc'!A1",
                          "-2+3+cmd|' /C calc'", "@SUM(1,9)"):
            out = sanitize_csv_field(dangerous)
            assert out.startswith("'"), f"{dangerous!r} was not neutralised"
            assert out[1:] == dangerous  # the original text itself is fully preserved, just prefixed

    def test_ordinary_values_are_never_touched(self):
        from app.reports.csv_report import sanitize_csv_field
        for ordinary in ("https://x.test/a.js", "DNS_FAILURE", "", None, 200, True):
            assert sanitize_csv_field(ordinary) == ordinary

    def test_malicious_resource_url_in_exported_csv_is_neutralised_end_to_end(self):
        import csv
        import io
        from app.models.db import SessionLocal, init_db
        from app.models.tables import Resource, Scan
        from app.reports.csv_report import build_scan_csv_report

        init_db()
        scan_id = "csvinject001"
        with SessionLocal() as db:
            db.add(Scan(scan_id=scan_id, target_url="https://x.test/", status="COMPLETED", scanner_version="t"))
            # A malicious page could plausibly cause a resource's error/url-derived
            # text to start with one of the dangerous characters (e.g. via a redirect
            # Location header or an exotic hostname) - simulated directly here.
            db.add(Resource(scan_id=scan_id, resource_id="r1", parent_resource_id=None,
                            parent_inferred=False, url="https://x.test/a.js", hostname="x.test",
                            port=443, scheme="https", resource_type="script", initiator="root",
                            load_status="FAILED", http_status=None,
                            error_text='=cmd|\' /C notepad\'!A1'))
            db.commit()
        with SessionLocal() as db:
            text = build_scan_csv_report(db, db.get(Scan, scan_id))
        rows = list(csv.DictReader(io.StringIO(text)))
        assert rows[0]["error_text"].startswith("'=")  # neutralised in the exported file
        # round-tripped as DATA (not opened in a spreadsheet), the original text,
        # including the leading apostrophe marker, is preserved byte for byte
        assert rows[0]["error_text"] == "'=cmd|' /C notepad'!A1"


# ================================================================================
# Finding 6: no limit on request body size. A malicious or buggy client could POST a
# JSON body of unbounded size, and the server would spend memory/CPU parsing the
# WHOLE thing before Pydantic's own schema validation (including the max_length
# constraints added alongside this) ever gets a chance to reject it. Fixed with a
# Content-Length-based rejection before Starlette reads the body at all.
# ================================================================================
class TestRequestBodySizeLimit:
    def test_oversized_body_rejected_with_413_before_parsing(self, client):
        # The middleware's limit is captured from settings at app-creation time (a
        # frozen dataclass), so this sends a payload genuinely larger than the real
        # default (1 MiB) rather than trying to shrink the limit after the fact.
        import json
        huge = json.dumps({"sites": [{"name": "x" * 50, "url": "https://x.test/" + "a" * 100}] * 6000}).encode()
        assert len(huge) > 1_048_576
        r = client.post("/api/batch-scan", content=huge, headers={"content-type": "application/json"})
        assert r.status_code == 413

    def test_normal_sized_body_is_unaffected(self, client):
        r = client.post("/api/batch-scan", json={"sites": [{"name": "x", "url": "https://x.test/"}],
                                                  "include_controlled": False})
        assert r.status_code == 202  # well under the default 1 MiB limit, works normally

    def test_get_requests_are_never_affected(self, client):
        assert client.get("/api/health").status_code == 200


# ================================================================================
# Finding 7: no limit on how many DISTINCT HOSTS one scan would probe. Phase 1's
# max_resources bounds total resources captured, but a page spread across hundreds of
# distinct hostnames (by design, or as a crude denial-of-service against the scanner
# itself) could still trigger unboundedly many outbound DNS/TCP/TLS/HTTP attempts.
# Fixed with an explicit cap; hosts beyond it are recorded as HOST_LIMIT_EXCEEDED
# (visibly "not tested because of a limit"), never silently dropped, and never
# connected to at all.
# ================================================================================
class TestMaxHostsPerScan:
    def _rows(self, n):
        return [{"hostname": f"host{i}.test", "port": 443} for i in range(n)]

    def test_hosts_beyond_the_cap_are_not_resolved_at_all(self):
        from app.scanner.dns_checker import DnsResolver
        from app.services.probe_service import run_dns_stage

        class CountingResolver(DnsResolver):
            def __init__(self):
                self.calls = 0
            async def lookup(self, host, family):
                self.calls += 1
                import app.scanner.dns_checker as d
                return d.DnsResult(family, d.OK, ["93.184.216.34"] if family == 4 else ["2001:db8::1"])

        resolver = CountingResolver()
        probes, host_dns = asyncio.run(run_dns_stage(self._rows(10), set(), resolver, 5, max_hosts=3))
        # only the first 3 DISCOVERED hosts actually got a real lookup (2 calls each: v4+v6)
        assert resolver.calls == 6
        excluded = [h for h, res in host_dns.items() if res[4].status == "HOST_LIMIT_EXCEEDED"]
        assert len(excluded) == 7

    def test_excluded_hosts_are_visible_not_silently_dropped(self):
        from app.scanner.dns_checker import DnsResolver
        from app.services.probe_service import run_dns_stage

        class FakeResolver(DnsResolver):
            async def lookup(self, host, family):
                import app.scanner.dns_checker as d
                return d.DnsResult(family, d.OK, ["93.184.216.34"])

        probes, host_dns = asyncio.run(run_dns_stage(self._rows(5), set(), FakeResolver(), 5, max_hosts=2))
        assert len(host_dns) == 5  # every host still appears - nothing vanishes from the results
        statuses = {h: res[4].status for h, res in host_dns.items()}
        kept = sum(1 for s in statuses.values() if s == "HOST_LIMIT_EXCEEDED")
        assert kept == 3
        excluded_detail = next(res[4].detail for res in host_dns.values() if res[4].status == "HOST_LIMIT_EXCEEDED")
        assert "host limit" in excluded_detail.lower()

    def test_excluded_host_resolves_to_not_tested_without_any_connection_attempt(self):
        """Confirms the family_probe fallback correctly handles the new status with
        ZERO changes needed there: NOT_TESTED, not a confirmed failure, and no TCP
        connection ever attempted for it."""
        from app.scanner.family_probe import probe_family
        from app.config import settings as cfg

        async def never_called(*a, **kw):
            raise AssertionError("must not attempt a connection for a host-limit-excluded host")

        out = asyncio.run(probe_family("excluded.test", 443, 6, scheme="https", path="/", addresses=[],
                                       dns_status="HOST_LIMIT_EXCEEDED",
                                       dns_detail="Scan already reached the configured host limit (3)",
                                       egress_ok=True, cfg=cfg, connect=never_called))
        assert out["verdict"] == "NOT_TESTED"
        assert out["failure_stage"] is None  # not a failure - a scope limit, a different thing entirely

    def test_no_cap_means_unchanged_behaviour(self):
        """max_hosts=None (the parameter's default) must behave exactly as before
        Phase 9 - no regression for the common case."""
        from app.scanner.dns_checker import DnsResolver
        from app.services.probe_service import run_dns_stage

        class FakeResolver(DnsResolver):
            async def lookup(self, host, family):
                import app.scanner.dns_checker as d
                return d.DnsResult(family, d.OK, ["93.184.216.34"])

        probes, host_dns = asyncio.run(run_dns_stage(self._rows(10), set(), FakeResolver(), 5))
        assert not any(res[4].status == "HOST_LIMIT_EXCEEDED" for res in host_dns.values())


# ================================================================================
# Finding 8: the new Fetch-domain interception sits on the main-document navigation
# path too, so a top-level redirect to a blocked address must degrade gracefully
# through the FULL run_scan pipeline (no hang, no crash, no fabricated success).
# ================================================================================
class TestBlockedMainNavigationDegradesGracefully:
    def test_top_level_redirect_to_metadata_address_ends_cleanly(self, allow_loopback, monkeypatch):
        import uuid
        from app.models.db import SessionLocal, init_db
        from app.models.tables import Scan
        from app.scanner.context import ScanContext
        from app.services import scan_runner

        def route(h):
            send_redirect(h, "http://169.254.169.254/latest/meta-data/")

        async def fake_ctx(force=False):
            return ScanContext(collected_at="2026-01-01T00:00:00Z", ipv4_egress_ok=True)

        monkeypatch.setattr(scan_runner, "get_context", fake_ctx)
        monkeypatch.setattr(scan_runner, "_sem", None)
        monkeypatch.setattr(scan_runner, "settings", fast_settings())
        init_db()
        srv = make_server(route)
        try:
            scan_id = uuid.uuid4().hex[:12]
            with SessionLocal() as db:
                db.add(Scan(scan_id=scan_id, target_url=f"http://127.0.0.1:{srv.server_address[1]}/",
                            scanner_version="t"))
                db.commit()
            try:
                asyncio.run(asyncio.wait_for(scan_runner.run_scan(scan_id), timeout=30))  # must not hang
            except Exception as e:  # noqa: BLE001
                if "Executable doesn't exist" in str(e):
                    pytest.skip("Chromium not installed")
                raise
            with SessionLocal() as db:
                scan = db.get(Scan, scan_id)
                if scan.status == "SCAN_FAILED" and "Executable doesn't exist" in (scan.error or ""):
                    pytest.skip("Chromium not installed")
                assert scan.status in ("PARTIAL", "BLOCKED", "SCAN_FAILED")  # never COMPLETED
                assert scan.status != "COMPLETED"
                assert scan.error and "BLOCKED_BY_CLIENT" in scan.error
        finally:
            srv.shutdown()
