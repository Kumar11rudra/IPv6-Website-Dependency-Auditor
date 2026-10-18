import asyncio
import dataclasses

from app.config import settings
from app.services.probe_service import probe_summary, run_family_probes


def rows():
    return [{"hostname": "ok.test", "port": 443, "scheme": "https", "url": "https://ok.test/a.js?token=SECRET"},
            {"hostname": "v4only.test", "port": 443, "scheme": "https", "url": "https://v4only.test/i.png"},
            {"hostname": "plain.test", "port": 80, "scheme": "http", "url": "http://plain.test/"}]


def probes():
    return [{"hostname": h, "port": p, "family": f, "dns_status": "OK", "dns_detail": None, "dns_addresses": ["1.2.3.4"]}
            for h, p in (("ok.test", 443), ("v4only.test", 443), ("plain.test", 80)) for f in (4, 6)]


def test_probes_classified_compared_and_summarised():
    seen = []
    async def fake(host, port, family, **kw):
        seen.append((host, family, kw["path"], kw["egress_ok"]))
        if host == "v4only.test" and family == 6:
            return {"verdict": "DNS_FAILURE", "failure_stage": "DNS"}
        return {"verdict": f"IPv{family}_REACHABLE", "failure_stage": None}
    ps = probes()
    asyncio.run(run_family_probes(ps, rows(), True, False, dataclasses.replace(settings), probe_fn=fake))
    assert all(p["family_comparison"] for p in ps)
    by = {(p["hostname"], p["family"]): p for p in ps}
    assert by["v4only.test", 6]["verdict"] == "DNS_FAILURE"
    assert ("ok.test", 6, "/a.js", False) in seen and ("ok.test", 4, "/a.js", True) in seen   # query string dropped, egress per family
    s = probe_summary(ps)
    assert s["by_family"]["ipv6"] == {"IPv6_REACHABLE": 2, "DNS_FAILURE": 1}
    assert s["unit"] == "host:port pairs"


def test_dual_stack_comparison_labels():
    async def fake(host, port, family, **kw):
        if host == "v4only.test" and family == 6:
            return {"verdict": "TCP_FAILURE", "failure_stage": "TCP"}
        return {"verdict": f"IPv{family}_REACHABLE", "failure_stage": None}
    ps = probes()
    asyncio.run(run_family_probes(ps, rows(), True, True, dataclasses.replace(settings), probe_fn=fake))
    cmp = {p["hostname"]: p["family_comparison"] for p in ps if p["family"] == 6}
    assert cmp == {"ok.test": "BOTH_OK", "v4only.test": "IPV6_BROKEN", "plain.test": "BOTH_OK"}
    assert probe_summary(ps)["ipv4_vs_ipv6"] == {"BOTH_OK": 2, "IPV6_BROKEN": 1}


def test_one_crashing_probe_does_not_lose_the_others():
    async def fake(host, port, family, **kw):
        if host == "ok.test" and family == 6:
            raise RuntimeError("boom")
        return {"verdict": f"IPv{family}_REACHABLE"}
    ps = probes()
    asyncio.run(run_family_probes(ps, rows(), True, True, dataclasses.replace(settings), probe_fn=fake))
    by = {(p["hostname"], p["family"]): p for p in ps}
    assert by["ok.test", 6]["verdict"] == "SCAN_FAILED" and "boom" in by["ok.test", 6]["error_detail"]
    assert by["plain.test", 4]["verdict"] == "IPv4_REACHABLE"
    assert by["ok.test", 6]["family_comparison"] == "INCONCLUSIVE"
