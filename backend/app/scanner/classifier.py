"""Failure classification. Pure functions, no I/O.

Stage order: DNS -> TCP -> TLS -> HTTP. The FIRST failing stage is the failure stage;
later stages are NOT_REACHED. Verdict names follow the brief:
  IPv6_REACHABLE / DNS_FAILURE / TCP_FAILURE / TLS_FAILURE / HTTP_FAILURE
plus BLOCKED, NOT_TESTED and SCAN_FAILED for states that are not IPv6 findings.
(Timeouts are a subtype of the stage they occur in, e.g. TCP_FAILURE/TIMEOUT.)
"""
from __future__ import annotations
from dataclasses import dataclass

PASS, FAIL = "PASS", "FAIL"
NOT_REACHED, NOT_TESTED, NOT_APPLICABLE = "NOT_REACHED", "NOT_TESTED", "NOT_APPLICABLE"


@dataclass
class StageResult:
    status: str
    subtype: str | None = None
    detail: str | None = None
    ms: int | None = None


def http_outcome(code: int) -> str:
    """Policy for a complete HTTP response over the tested family.

    5xx            -> FAIL     (server/edge broken on this path)
    401/403/429    -> BLOCKED  (transport worked; the server refused us: bot wall, hotlink
                                protection, rate limit. Not evidence about IPv6.)
    anything else  -> PASS     (incl. 3xx and 404: the network path works)
    """
    if 500 <= code <= 599:
        return FAIL
    if code in (401, 403, 429):
        return "BLOCKED"
    return PASS


def verdict(family: int, failure_stage: str | None, *, blocked: bool = False, not_tested: bool = False) -> str:
    if not_tested:
        return "NOT_TESTED"
    if blocked:
        return "BLOCKED"
    if failure_stage:
        return f"{failure_stage}_FAILURE"
    return f"IPv{family}_REACHABLE"


def compare(v4: str, v6: str) -> str:
    """Relate the IPv4 and IPv6 verdicts of the same host:port.
    IPV6_BROKEN = works over IPv4 but not IPv6 (what the brief calls an IPv4-only dependency)."""
    if v4 in ("NOT_TESTED", "BLOCKED", "SCAN_FAILED") or v6 in ("NOT_TESTED", "BLOCKED", "SCAN_FAILED"):
        return "INCONCLUSIVE"
    ok4, ok6 = v4.endswith("_REACHABLE"), v6.endswith("_REACHABLE")
    if ok4 and ok6:
        return "BOTH_OK"
    if ok4:
        return "IPV6_BROKEN"
    if ok6:
        return "IPV4_BROKEN"
    return "BOTH_BROKEN"
