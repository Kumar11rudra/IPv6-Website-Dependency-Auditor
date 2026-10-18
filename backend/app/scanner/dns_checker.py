"""Per-family DNS lookups (A / AAAA) using the scanner host's system resolver.

A DNS answer only says an address is *advertised*. It says nothing about whether
that address is reachable; that is tested separately (TCP/TLS/HTTP, Phase 3).

Statuses distinguish "the name has no record of this type" (NO_RECORD) from
"the lookup itself failed" (TIMEOUT / RESOLUTION_ERROR / NXDOMAIN).
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

OK = "OK"
NO_RECORD = "NO_RECORD"
NXDOMAIN = "NXDOMAIN"
TIMEOUT = "TIMEOUT"
RESOLUTION_ERROR = "RESOLUTION_ERROR"
LITERAL = "LITERAL"                # hostname is an IP literal; no lookup needed
NOT_APPLICABLE = "NOT_APPLICABLE"  # e.g. IPv6 test of a host given as an IPv4 literal
BLOCKED = "BLOCKED"                # resolved to a non-public address; SSRF policy
HOST_LIMIT_EXCEEDED = "HOST_LIMIT_EXCEEDED"  # Phase 9: scan already probed max_hosts_per_scan distinct hosts

DNS_FAILURE_STATUSES = {NO_RECORD, NXDOMAIN, TIMEOUT, RESOLUTION_ERROR}


@dataclass
class DnsResult:
    family: int
    status: str
    addresses: list[str] = field(default_factory=list)
    detail: str | None = None
    canonical_name: str | None = None
    resolver_used: str | None = None
    elapsed_ms: int | None = None


class DnsResolver:
    def __init__(self, timeout_s: float = 5.0, resolver=None) -> None:
        if resolver is None:
            resolver = dns.asyncresolver.Resolver(configure=True)
            resolver.lifetime = timeout_s
            resolver.timeout = min(2.0, timeout_s)
        self._r = resolver

    async def lookup(self, host: str, family: int) -> DnsResult:
        rdtype = "AAAA" if family == 6 else "A"
        t0 = time.monotonic()

        def done(status: str, **kw) -> DnsResult:
            return DnsResult(family=family, status=status, elapsed_ms=int((time.monotonic() - t0) * 1000), **kw)

        try:
            ans = await self._r.resolve(host, rdtype, raise_on_no_answer=True)
        except dns.resolver.NoAnswer:
            return done(NO_RECORD, detail=f"Name exists but has no {rdtype} record (NOERROR/NODATA)")
        except dns.resolver.NXDOMAIN:
            return done(NXDOMAIN, detail="Name does not exist (NXDOMAIN)")
        except dns.exception.Timeout:
            return done(TIMEOUT, detail="DNS query timed out")
        except dns.resolver.NoNameservers as e:
            return done(RESOLUTION_ERROR, detail=f"All nameservers failed (SERVFAIL/REFUSED): {str(e)[:200]}")
        except (dns.exception.DNSException, OSError) as e:
            return done(RESOLUTION_ERROR, detail=f"{type(e).__name__}: {str(e)[:200]}")

        addrs = sorted({r.address for r in ans})
        used = getattr(ans, "nameserver", None)
        canon = getattr(ans, "canonical_name", None)
        return done(
            OK if addrs else NO_RECORD,
            addresses=addrs,
            canonical_name=str(canon).rstrip(".") if canon is not None else None,
            resolver_used=str(used) if used else None,
        )
