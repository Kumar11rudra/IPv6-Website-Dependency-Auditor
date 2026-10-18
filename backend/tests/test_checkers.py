import asyncio
import errno
import ssl

import pytest

from app.scanner import http_checker as H
from app.scanner import tcp_checker as T


@pytest.mark.parametrize("exc,subtype", [
    (asyncio.TimeoutError(), "TIMEOUT"), (TimeoutError(), "TIMEOUT"),
    (ConnectionRefusedError(), "REFUSED"), (ConnectionResetError(), "RESET"),
    (OSError(errno.ENETUNREACH, "Network is unreachable"), "UNREACHABLE"),
    (OSError(errno.EHOSTUNREACH, "No route to host"), "UNREACHABLE"),
    (OSError(errno.EAFNOSUPPORT, "Address family not supported"), "UNREACHABLE"),
    (OSError(errno.ETIMEDOUT, "timed out"), "TIMEOUT"),          # ETIMEDOUT surfaces as TimeoutError
    (OSError(errno.EPERM, "nope"), "ERROR"),
])
def test_tcp_error_classification(exc, subtype):
    if subtype == "TIMEOUT" and type(exc) is OSError:
        exc = TimeoutError(errno.ETIMEDOUT, "timed out")
    assert T.classify_error(exc)[0] == subtype


def test_status_line_parsing():
    assert H.parse_status_line(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\n") == 200
    assert H.parse_status_line(b"HTTP/1.0 503\r\n\r\n") == 503
    for bad in (b"garbage\r\n\r\n", b"HTTP/2 200\r\n\r\n", b"HTTP/1.1 999 x\r\n\r\n", b"HTTP/1.1 20 x\r\n\r\n", b""):
        assert H.parse_status_line(bad) is None


def test_request_building_is_injection_safe():
    req = H.build_request("example.com", 443, "https", "/a/b.js", "ua").decode()
    assert req.startswith("GET /a/b.js HTTP/1.1\r\nHost: example.com\r\n") and "Range: bytes=0-0" in req
    assert "Host: example.com:8443" in H.build_request("example.com", 8443, "https", "/", "ua").decode()
    assert "Host: [2606:4700::1]" in H.build_request("2606:4700::1", 443, "https", "/", "ua").decode()
    evil = H.build_request("example.com", 80, "http", "/x HTTP/1.1\r\nX-Injected: 1", "ua").decode()
    assert "X-Injected" not in evil and evil.startswith("GET / HTTP/1.1")
    with pytest.raises(ValueError):
        H.build_request("evil.com\r\nX: y", 80, "http", "/", "ua")
