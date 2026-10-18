"""Failure classification against REAL sockets (IPv4 loopback; IPv6 loopback when the host has it)."""
import asyncio
import dataclasses

import pytest

from app.config import settings
from app.scanner import classifier as C
from app.scanner.family_probe import probe_family
from tests import netfixtures as N

HOST = "site.test"


@pytest.fixture(autouse=True)
def allow_loopback(monkeypatch):
    monkeypatch.setattr("app.scanner.ssrf_guard.settings",
                        dataclasses.replace(settings, ssrf_allow_hosts=(HOST,)))


def run(coro):
    return asyncio.run(coro)


def probe(port, *, family=4, scheme="http", addresses=("127.0.0.1",), dns_status="OK", egress=True, tls_context=None, **kw):
    return probe_family(HOST, port, family, scheme=scheme, path="/x.js", dns_status=dns_status,
                        dns_detail=kw.get("dns_detail"), addresses=list(addresses), egress_ok=egress, cfg=N.CFG,
                        tls_context=tls_context)


def stages(o):
    return o["tcp_status"], o["tls_status"], o["http_stage_status"]


# ------------------------------------------------------------------ success
def test_plain_http_reachable():
    async def go():
        srv, port = await N.start("ok")
        try:
            return await probe(port)
        finally:
            srv.close()
    o = run(go())
    assert o["verdict"] == "IPv4_REACHABLE" and o["failure_stage"] is None
    assert stages(o) == ("PASS", "NOT_APPLICABLE", "PASS") and o["http_code"] == 200
    assert o["connected_address"] == "127.0.0.1" and o["tcp_ms"] is not None


def test_https_reachable_with_trusted_cert(tmp_path):
    ca_key, ca = N.make_ca()
    cert, key = N.issue(ca_key, ca, HOST, tmp_path)
    async def go():
        srv, port = await N.start("ok", ssl_ctx=N.server_ctx(cert, key))
        try:
            return await probe(port, scheme="https", tls_context=N.client_ctx_trusting(ca, tmp_path))
        finally:
            srv.close()
    o = run(go())
    assert o["verdict"] == "IPv4_REACHABLE" and stages(o) == ("PASS", "PASS", "PASS")
    assert o["tls_version"] in ("TLSv1.2", "TLSv1.3") and o["tls_ms"] is not None


# ------------------------------------------------------------------ one failure per stage
def test_dns_failure_no_record():
    o = run(probe(1, dns_status="NO_RECORD", addresses=(), dns_detail="Name exists but has no AAAA record", family=6))
    assert o["verdict"] == "DNS_FAILURE" and o["failure_stage"] == "DNS" and o["failure_subtype"] == "NO_RECORD"
    assert stages(o) == ("NOT_REACHED", "NOT_APPLICABLE", "NOT_REACHED")
    o = run(probe(1, dns_status="TIMEOUT", addresses=(), scheme="https", family=6))
    assert stages(o) == ("NOT_REACHED", "NOT_REACHED", "NOT_REACHED") and o["failure_subtype"] == "TIMEOUT"


def test_tcp_failure_refused():
    o = run(probe(N.closed_port()))
    assert o["verdict"] == "TCP_FAILURE" and o["failure_stage"] == "TCP" and o["failure_subtype"] == "REFUSED"
    assert stages(o) == ("FAIL", "NOT_APPLICABLE", "NOT_REACHED") and "127.0.0.1: REFUSED" in o["error_detail"]


def test_tls_failure_server_not_speaking_tls():
    async def go():
        srv, port = await N.start("ok")           # plain HTTP server, client attempts TLS
        try:
            return await probe(port, scheme="https")
        finally:
            srv.close()
    o = run(go())
    assert o["verdict"] == "TLS_FAILURE" and o["failure_stage"] == "TLS"
    # A plain-HTTP server never answers the ClientHello, so asyncio's own ssl_handshake_timeout
    # fires deterministically. It raises ConnectionAbortedError, not TimeoutError - verified directly
    # against asyncio's behavior, not assumed.
    assert o["failure_subtype"] == "TIMEOUT" and stages(o) == ("PASS", "FAIL", "NOT_REACHED")


def test_tls_failure_untrusted_certificate(tmp_path):
    ca_key, ca = N.make_ca()
    cert, key = N.issue(ca_key, ca, HOST, tmp_path)
    async def go():
        srv, port = await N.start("ok", ssl_ctx=N.server_ctx(cert, key))
        try:
            return await probe(port, scheme="https")     # default trust store does not know the test CA
        finally:
            srv.close()
    o = run(go())
    assert o["verdict"] == "TLS_FAILURE" and o["failure_subtype"] == "CERT_VERIFY"
    assert o["tcp_status"] == "PASS" and o["http_stage_status"] == "NOT_REACHED"


def test_tls_failure_wrong_hostname(tmp_path):
    ca_key, ca = N.make_ca()
    cert, key = N.issue(ca_key, ca, "other.test", tmp_path)
    async def go():
        srv, port = await N.start("ok", ssl_ctx=N.server_ctx(cert, key))
        try:
            return await probe(port, scheme="https", tls_context=N.client_ctx_trusting(ca, tmp_path))
        finally:
            srv.close()
    o = run(go())
    assert o["verdict"] == "TLS_FAILURE" and o["failure_subtype"] == "CERT_VERIFY"
    assert "match" in o["error_detail"].lower() or "hostname" in o["error_detail"].lower()


@pytest.mark.parametrize("behavior,subtypes", [
    ("drop", {"NO_RESPONSE", "RESET"}), ("garbage", {"MALFORMED"}), ("silent", {"TIMEOUT"}),
])
def test_http_failures_after_working_tcp(behavior, subtypes):
    async def go():
        srv, port = await N.start(behavior)
        try:
            return await probe(port)
        finally:
            srv.close()
    o = run(go())
    assert o["verdict"] == "HTTP_FAILURE" and o["failure_stage"] == "HTTP" and o["failure_subtype"] in subtypes
    assert stages(o)[0] == "PASS" and stages(o)[2] == "FAIL"


def test_http_500_is_http_failure_but_404_is_not():
    async def go(code):
        srv, port = await N.start("ok", code=code)
        try:
            return await probe(port)
        finally:
            srv.close()
    o = run(go(500))
    assert o["verdict"] == "HTTP_FAILURE" and o["failure_subtype"] == "SERVER_ERROR" and o["http_code"] == 500
    o = run(go(404))
    assert o["verdict"] == "IPv4_REACHABLE" and o["http_code"] == 404


def test_403_is_blocked_not_a_failure():
    async def go():
        srv, port = await N.start("ok", code=403)
        try:
            return await probe(port)
        finally:
            srv.close()
    o = run(go())
    assert o["verdict"] == "BLOCKED" and o["failure_stage"] is None and stages(o) == ("PASS", "NOT_APPLICABLE", "PASS")


# ------------------------------------------------------------------ multi-address behaviour
def test_partial_addresses_still_reachable_but_flagged():
    async def go():
        srv, port = await N.start("ok")           # only 127.0.0.1 listens; 127.0.0.2 is refused
        try:
            return await probe(port, addresses=("127.0.0.2", "127.0.0.1"))
        finally:
            srv.close()
    o = run(go())
    assert o["verdict"] == "IPv4_REACHABLE" and o["connected_address"] == "127.0.0.1"
    assert (o["addresses_tested"], o["addresses_reachable"]) == (2, 1) and "Partial" in o["error_detail"]


def test_all_addresses_failing_reports_each():
    o = run(probe(N.closed_port(), addresses=("127.0.0.1", "127.0.0.2")))
    assert o["verdict"] == "TCP_FAILURE" and "127.0.0.1: REFUSED" in o["error_detail"] and (
        "127.0.0.2: REFUSED" in o["error_detail"] or "127.0.0.2: TIMEOUT" in o["error_detail"]
    )


# ------------------------------------------------------------------ non-findings
def test_no_ipv6_egress_is_not_tested_never_a_failure():
    o = run(probe(80, family=6, addresses=("2606:4700::1",), egress=False))
    assert o["verdict"] == "NOT_TESTED" and o["failure_stage"] is None and "no IPv6 egress" in o["error_detail"]
    assert stages(o)[0] == "NOT_TESTED"


def test_dns_failure_is_still_reported_without_ipv6_egress():
    o = run(probe(80, family=6, dns_status="NO_RECORD", addresses=(), egress=False))
    assert o["verdict"] == "DNS_FAILURE"      # DNS needs no IPv6 egress, so this finding is valid


def test_unknown_egress_still_probes():
    async def go():
        srv, port = await N.start("ok")
        try:
            return await probe(port, egress=None)
        finally:
            srv.close()
    assert run(go())["verdict"] == "IPv4_REACHABLE"


def test_blocked_and_not_applicable_dns_states():
    assert run(probe(80, dns_status="BLOCKED", addresses=("10.0.0.1",)))["verdict"] == "BLOCKED"
    assert run(probe(80, family=6, dns_status="NOT_APPLICABLE", addresses=()))["verdict"] == "NOT_TESTED"


def test_ssrf_defence_in_depth_refuses_private_address(monkeypatch):
    monkeypatch.setattr("app.scanner.ssrf_guard.settings", dataclasses.replace(settings, ssrf_allow_hosts=()))
    called = []
    async def spy(*a, **k):
        called.append(1)
    o = run(probe_family("evil.test", 80, 4, scheme="http", path="/", dns_status="OK", addresses=["10.0.0.5"],
                         egress_ok=True, cfg=N.CFG, connect=spy))
    assert o["verdict"] == "BLOCKED" and not called      # never even attempted a connection


def test_tcp_timeout_via_injected_connect():
    async def dropped(addresses, port, family, timeout):
        return None, [{"address": a, "ok": False, "subtype": "TIMEOUT", "detail": "x"} for a in addresses]
    o = run(probe_family("site.test", 443, 6, scheme="https", path="/", dns_status="OK",
                         addresses=["2606:4700::1"], egress_ok=True, cfg=N.CFG, connect=dropped))
    assert o["verdict"] == "TCP_FAILURE" and o["failure_subtype"] == "TIMEOUT"
    assert stages(o) == ("FAIL", "NOT_REACHED", "NOT_REACHED")


# ------------------------------------------------------------------ real IPv6 (only where the host supports it)
@pytest.mark.skipif(not N.ipv6_loopback_available(), reason="no IPv6 loopback on this host")
def test_real_ipv6_reachable_and_refused():
    async def go():
        srv, port = await N.start("ok", host="::1")
        try:
            ok = await probe(port, family=6, addresses=("::1",))
        finally:
            srv.close()
        refused = await probe(port, family=6, addresses=("::1",))
        return ok, refused
    ok, refused = run(go())
    assert ok["verdict"] == "IPv6_REACHABLE"
    assert refused["verdict"] == "TCP_FAILURE" and refused["failure_subtype"] == "REFUSED"
