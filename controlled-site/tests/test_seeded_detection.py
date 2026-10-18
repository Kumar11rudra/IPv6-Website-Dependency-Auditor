"""Proves the scanner's own classifier (backend/app/scanner/family_probe.py) correctly
detects every failure stage this controlled site seeds. This is the automated evidence
for PS-027 requirement 4: "Detect all deliberately seeded IPv4-only resources."

Limitation, stated plainly: this dev/CI environment has no real IPv6, so the "IPv6 path"
of each seeded host is simulated with a second IPv4 loopback ALIAS (127.0.0.2) rather than
a real IPv6 address. seed_server.py's branching logic (what happens on each bind address)
is address-family-agnostic, and the scanner's classifier is equally agnostic once it has
an address to test - so this exercises the real detection logic end to end. It does not,
by itself, prove the scanner's raw socket code path for AF_INET6 works; that is covered by
the IPv6-loopback-guarded tests in backend/tests/test_family_probe.py, and finally by
running this same site with real AAAA records on the dual-stack VPS (see deploy/DEPLOY.md).
"""
import asyncio
import dataclasses
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server" / "seed_server.py"
CERT = ROOT / "server" / "dev.crt"
KEY = ROOT / "server" / "dev.key"
CONTENT = ROOT / "content"
HOST = "controlled-test.example"

sys.path.insert(0, str(ROOT.parent / "backend"))
from app.config import settings  # noqa: E402
from app.scanner import ssrf_guard as sg  # noqa: E402
from app.scanner.family_probe import probe_family  # noqa: E402

CFG = dataclasses.replace(settings, tcp_timeout_s=2, tls_timeout_s=2, http_timeout_s=2)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def setup_module(_module):
    global _original_settings
    _original_settings = sg.settings
    sg.settings = dataclasses.replace(_original_settings, ssrf_allow_hosts=(HOST,))


def teardown_module(_module):
    sg.settings = _original_settings


class SeededServer:
    """Starts seed_server.py as a real subprocess for one scenario and tears it down after."""

    def __init__(self):
        self.procs = []

    def start(self, v6_mode: str, scheme: str = "http", with_v6: bool = True) -> int:
        port = free_port()
        v6_port = free_port()
        cmd = [sys.executable, str(SERVER), "--content-dir", str(CONTENT),
              "--v4-bind", f"127.0.0.1:{port}"]
        if with_v6:
            cmd += ["--v6-bind", f"127.0.0.1:{v6_port}", "--v6-mode", v6_mode]
        if scheme == "https":
            cmd += ["--scheme", "https", "--cert", str(CERT), "--key", str(KEY)]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(proc)
        time.sleep(0.4)
        return v6_port if with_v6 else port

    def stop_all(self):
        for p in self.procs:
            p.kill()
            p.wait(timeout=2)


def probe_v6_stand_in(port: int, scheme: str, tls_ctx=None):
    return asyncio.run(probe_family(HOST, port, 4, scheme=scheme, path="/index.html", dns_status="OK",
                                    addresses=["127.0.0.1"], egress_ok=True, cfg=CFG, tls_context=tls_ctx))


def test_dual_stack_host_is_reachable():
    srv = SeededServer()
    try:
        port = srv.start("pass")
        out = probe_v6_stand_in(port, "http")
        assert out["verdict"] == "IPv4_REACHABLE" and out["failure_stage"] is None
    finally:
        srv.stop_all()


def test_seeded_tcp_failure_detected():
    srv = SeededServer()
    try:
        port = srv.start("tcp_fail")
        out = probe_v6_stand_in(port, "http")
        assert out["verdict"] == "TCP_FAILURE" and out["failure_stage"] == "TCP"
        assert out["failure_subtype"] == "REFUSED"
    finally:
        srv.stop_all()


def test_seeded_tls_failure_detected():
    srv = SeededServer()
    try:
        port = srv.start("tls_fail", scheme="https")
        ctx = ssl.create_default_context(cafile=str(CERT))
        out = probe_v6_stand_in(port, "https", tls_ctx=ctx)
        assert out["verdict"] == "TLS_FAILURE" and out["failure_stage"] == "TLS"
        assert out["tcp_status"] == "PASS"  # confirms TCP genuinely succeeded before TLS broke
    finally:
        srv.stop_all()


def test_seeded_http_failure_detected():
    srv = SeededServer()
    try:
        port = srv.start("http_fail", scheme="https")
        ctx = ssl.create_default_context(cafile=str(CERT))
        out = probe_v6_stand_in(port, "https", tls_ctx=ctx)
        assert out["verdict"] == "HTTP_FAILURE" and out["failure_stage"] == "HTTP"
        assert out["tcp_status"] == "PASS" and out["tls_status"] == "PASS"
        assert out["http_code"] == 500
    finally:
        srv.stop_all()


def test_seeded_dns_only_failure_detected():
    """v4only-img: no AAAA record at all. No server needed; DNS_FAILURE is a pure DNS-stage
    finding, exactly as Phase 2/3 classify a real 'no AAAA record' host."""
    out = asyncio.run(probe_family(f"v4only-img.{HOST}", 443, 4, scheme="https", path="/images/photo.png",
                                   dns_status="NO_RECORD", dns_detail="No AAAA record", addresses=[],
                                   egress_ok=True, cfg=CFG))
    assert out["verdict"] == "DNS_FAILURE" and out["failure_stage"] == "DNS"
    assert out["failure_subtype"] == "NO_RECORD"


def test_seeded_manifest_is_internally_consistent():
    import json
    manifest = json.loads((ROOT / "seeded.json").read_text())
    stages = {"DNS", "TCP", "TLS", "HTTP"}
    seen_stages = set()
    for r in manifest["resources"]:
        assert {"hostname", "resource", "type", "dns", "expected_ipv6_outcome"} <= r.keys()
        outcome = r["expected_ipv6_outcome"]
        assert outcome == "IPv6_REACHABLE" or outcome.endswith("_FAILURE")
        if outcome != "IPv6_REACHABLE":
            assert r["expected_failure_stage"] in stages
            seen_stages.add(r["expected_failure_stage"])
    assert seen_stages == stages  # every failure stage is represented at least once
