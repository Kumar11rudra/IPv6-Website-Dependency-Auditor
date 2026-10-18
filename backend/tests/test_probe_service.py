import asyncio

from app.scanner import dns_checker as d
from app.services.probe_service import dns_summary, run_dns_stage


class FakeDns:
    def __init__(self, table):
        self.table = table
        self.calls = []

    async def lookup(self, host, family):
        self.calls.append((host, family))
        status, addrs = self.table.get((host, family), (d.NO_RECORD, []))
        return d.DnsResult(family, status, addrs, None if status == d.OK else "x", resolver_used="9.9.9.9", elapsed_ms=1)


def row(host, port=443):
    return {"hostname": host, "port": port, "ipv4_addresses": [], "ipv6_addresses": []}


def test_dns_stage_per_family_and_address_fill():
    fake = FakeDns({
        ("ok.test", 4): (d.OK, ["93.184.216.34"]), ("ok.test", 6): (d.OK, ["2606:2800::1"]),
        ("v4only.test", 4): (d.OK, ["93.184.216.35"]),   # no AAAA -> NO_RECORD
        ("broken.test", 4): (d.OK, ["93.184.216.36"]), ("broken.test", 6): (d.TIMEOUT, []),
    })
    rows = [row("ok.test"), row("ok.test"), row("v4only.test"), row("broken.test"), row("ok.test", 8443)]
    probes, host_dns = asyncio.run(run_dns_stage(rows, set(), fake))
    assert sorted(set(fake.calls)) == sorted({(h, f) for h in ("ok.test", "v4only.test", "broken.test") for f in (4, 6)})
    assert len(fake.calls) == 6                         # each host resolved once per family, not per resource
    by = {(p["hostname"], p["port"], p["family"]): p for p in probes}
    assert len(probes) == 8                             # 4 (host,port) pairs x 2 families
    assert by["v4only.test", 443, 6]["dns_status"] == d.NO_RECORD
    assert by["broken.test", 443, 6]["dns_status"] == d.TIMEOUT
    assert by["ok.test", 8443, 4]["dns_addresses"] == ["93.184.216.34"]
    assert rows[0]["ipv6_addresses"] == ["2606:2800::1"] and rows[2]["ipv6_addresses"] == []
    s = dns_summary(host_dns)
    assert s["hosts"] == 3 and s["hosts_advertising_aaaa"] == 1 and s["aaaa_no_record"] == 1 and s["aaaa_lookup_errors"] == 1


def test_ip_literals_and_blocked_hosts_are_not_looked_up():
    fake = FakeDns({})
    rows = [row("93.184.216.34"), row("2606:2800::1"), row("internal.test")]
    probes, _ = asyncio.run(run_dns_stage(rows, {"internal.test"}, fake))
    assert fake.calls == []
    by = {(p["hostname"], p["family"]): p["dns_status"] for p in probes}
    assert by["93.184.216.34", 4] == d.LITERAL and by["93.184.216.34", 6] == d.NOT_APPLICABLE
    assert by["2606:2800::1", 6] == d.LITERAL and by["2606:2800::1", 4] == d.NOT_APPLICABLE
    assert by["internal.test", 4] == d.BLOCKED and by["internal.test", 6] == d.BLOCKED


def test_public_name_resolving_to_private_address_is_blocked():
    fake = FakeDns({("sneaky.test", 4): (d.OK, ["10.0.0.7"]), ("sneaky.test", 6): (d.OK, ["2606:2800::1"])})
    rows = [row("sneaky.test")]
    probes, _ = asyncio.run(run_dns_stage(rows, set(), fake))
    by = {p["family"]: p["dns_status"] for p in probes}
    assert by[4] == d.BLOCKED and by[6] == d.OK
    assert rows[0]["ipv4_addresses"] == []              # blocked addresses are not exposed as usable
