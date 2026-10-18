import asyncio
from types import SimpleNamespace

import dns.exception
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from app.scanner import dns_checker as d


class FakeResolver:
    def __init__(self, outcome):
        self.outcome = outcome

    async def resolve(self, host, rdtype, **kw):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def lookup(outcome, fam=6):
    return asyncio.run(d.DnsResolver(resolver=FakeResolver(outcome)).lookup("h.test", fam))


@pytest.mark.parametrize("exc,status", [
    (dns.resolver.NoAnswer(), d.NO_RECORD),
    (dns.resolver.NXDOMAIN(), d.NXDOMAIN),
    (dns.resolver.LifetimeTimeout(timeout=5, errors=[]), d.TIMEOUT),
    (dns.resolver.NoNameservers(request=dns.message.make_query("h.test", "AAAA"), errors=[("1.1.1.1", False, 53, "SERVFAIL", None)]), d.RESOLUTION_ERROR),
    (OSError("Network is unreachable"), d.RESOLUTION_ERROR),
    (dns.name.EmptyLabel(), d.RESOLUTION_ERROR),
])
def test_error_mapping(exc, status):
    r = lookup(exc)
    assert r.status == status and r.addresses == [] and r.detail


def test_no_record_is_distinct_from_lookup_failure():
    assert lookup(dns.resolver.NoAnswer()).status != lookup(dns.resolver.LifetimeTimeout(timeout=1, errors=[])).status


def test_real_dnspython_answer_object_with_cname():
    msg = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nwww.example.com. IN AAAA\n"
        ";ANSWER\nwww.example.com. 300 IN CNAME edge.example.net.\nedge.example.net. 300 IN AAAA 2001:db8::2\n"
        "edge.example.net. 300 IN AAAA 2001:db8::1\n")
    ans = dns.resolver.Answer(dns.name.from_text("www.example.com."), dns.rdatatype.AAAA,
                              dns.rdataclass.IN, msg, "9.9.9.9", 53)
    r = lookup(ans)
    assert r.status == d.OK and r.addresses == ["2001:db8::1", "2001:db8::2"]
    assert r.canonical_name == "edge.example.net" and r.resolver_used == "9.9.9.9"
