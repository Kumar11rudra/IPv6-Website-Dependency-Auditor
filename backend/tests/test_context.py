import asyncio
import json

from app.scanner import context as c

RESOLV = "# comment\nnameserver 127.0.0.53\nnameserver ::1\nnameserver bogus\noptions edns0\nsearch x\n"
UPSTREAM = "nameserver 192.0.2.53\nnameserver 2001:db8::53\n"


def test_parse_nameservers():
    assert c.parse_nameservers(RESOLV) == ["127.0.0.53", "::1"]
    assert c.parse_nameservers("") == []


def test_stub_resolver_reads_upstreams(tmp_path):
    (tmp_path / "r").write_text(RESOLV)
    (tmp_path / "u").write_text(UPSTREAM)
    ctx = c.ScanContext(collected_at="t")
    c._fill_resolvers(ctx, str(tmp_path / "r"), str(tmp_path / "u"))
    assert ctx.resolver_is_local_stub and ctx.resolver_upstream_ips == ["192.0.2.53", "2001:db8::53"]


def test_missing_resolv_conf_is_unknown(tmp_path):
    ctx = c.ScanContext(collected_at="t")
    c._fill_resolvers(ctx, str(tmp_path / "nope"), str(tmp_path / "nope2"))
    d = ctx.display()
    assert d["resolver_ips"] == "Unknown" and d["resolver_is_local_stub"] == "Unknown"


def collect(tcp, http, who=None, **kw):
    async def whoami():
        return who
    return asyncio.run(c.collect_context(tcp=tcp, http_get=http, whoami=whoami, resolv_conf="/nonexistent",
                                         systemd_resolv="/nonexistent", **kw))


async def tcp_ok(h, p, fam, t):
    return True


def test_dual_stack_happy_path():
    async def http(url, fam, t):
        if url == c.PUBLIC_IP_URL:
            return "93.184.216.34" if fam == 4 else "2606:4700::7"
        return json.dumps({"ip": "93.184.216.34", "city": "Mumbai", "region": "MH", "country": "IN", "org": "AS64500 Example"})
    ctx = collect(tcp_ok, http, who="198.51.100.9")
    assert (ctx.ipv4_egress_ok, ctx.ipv6_egress_ok) == (True, True) and not ctx.warnings
    assert ctx.scanner_public_ipv4 == "93.184.216.34" and ctx.scanner_public_ipv6 == "2606:4700::7"
    assert ctx.geo_country == "IN" and ctx.geo_source == "ipinfo.io" and ctx.geo_ip == "93.184.216.34"
    assert ctx.resolver_egress_ip == "198.51.100.9"


def test_no_ipv6_egress_is_flagged_not_failed():
    async def tcp(h, p, fam, t):
        return fam == 4
    async def http(url, fam, t):
        assert fam == 4   # never tries IPv6 when egress is down
        return "93.184.216.34" if url == c.PUBLIC_IP_URL else json.dumps({"country": "IN"})
    ctx = collect(tcp, http)
    assert ctx.ipv6_egress_ok is False and ctx.scanner_public_ipv6 is None
    assert any("NOT_TESTED" in w for w in ctx.warnings)


def test_everything_fails_gives_unknown_never_invented():
    async def tcp(h, p, fam, t):
        raise RuntimeError("boom")
    async def http(url, fam, t):
        return None
    ctx = collect(tcp, http)
    disp = ctx.display()
    for k in ("ipv4_egress_ok", "ipv6_egress_ok", "scanner_public_ipv4", "geo_country", "geo_city", "resolver_egress_ip"):
        assert disp[k] == "Unknown", k


def test_geo_falls_back_and_rejects_garbage():
    async def http(url, fam, t):
        if url == c.PUBLIC_IP_URL:
            return "<html>captive portal</html>" if fam == 6 else "93.184.216.34"
        if "ipinfo.io" in url:
            return json.dumps({"ip": "93.184.216.34", "bogon": True})
        return json.dumps({"success": True, "country_code": "IN", "city": "Delhi", "region": "DL",
                           "connection": {"org": "Example ISP"}})
    ctx = collect(tcp_ok, http)
    assert ctx.scanner_public_ipv6 is None            # garbage rejected
    assert ctx.geo_source == "ipwho.is" and ctx.geo_city == "Delhi" and ctx.geo_org == "Example ISP"


def test_private_ip_from_lookup_is_rejected():
    assert c._valid_public_ip("10.0.0.5", 4) is None
    assert c._valid_public_ip("2001:db8::1", 4) is None
