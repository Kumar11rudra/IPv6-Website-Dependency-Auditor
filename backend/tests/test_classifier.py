import pytest

from app.scanner import classifier as C


@pytest.mark.parametrize("code,expected", [(200, "PASS"), (204, "PASS"), (301, "PASS"), (404, "PASS"), (416, "PASS"),
                                           (500, "FAIL"), (502, "FAIL"), (503, "FAIL"), (599, "FAIL"),
                                           (401, "BLOCKED"), (403, "BLOCKED"), (429, "BLOCKED")])
def test_http_outcome(code, expected):
    assert C.http_outcome(code) == expected


def test_verdict_names():
    assert C.verdict(6, None) == "IPv6_REACHABLE" and C.verdict(4, None) == "IPv4_REACHABLE"
    for stage in ("DNS", "TCP", "TLS", "HTTP"):
        assert C.verdict(6, stage) == f"{stage}_FAILURE"
    assert C.verdict(6, None, blocked=True) == "BLOCKED"
    assert C.verdict(6, None, not_tested=True) == "NOT_TESTED"


@pytest.mark.parametrize("v4,v6,expected", [
    ("IPv4_REACHABLE", "IPv6_REACHABLE", "BOTH_OK"),
    ("IPv4_REACHABLE", "DNS_FAILURE", "IPV6_BROKEN"),
    ("IPv4_REACHABLE", "TCP_FAILURE", "IPV6_BROKEN"),
    ("DNS_FAILURE", "IPv6_REACHABLE", "IPV4_BROKEN"),
    ("HTTP_FAILURE", "HTTP_FAILURE", "BOTH_BROKEN"),          # e.g. origin down: not IPv6-specific
    ("IPv4_REACHABLE", "NOT_TESTED", "INCONCLUSIVE"),
    ("BLOCKED", "IPv6_REACHABLE", "INCONCLUSIVE"),
    ("IPv4_REACHABLE", "SCAN_FAILED", "INCONCLUSIVE"),
])
def test_compare(v4, v6, expected):
    assert C.compare(v4, v6) == expected
