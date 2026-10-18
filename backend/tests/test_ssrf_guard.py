import asyncio

import pytest

from app.scanner.ssrf_guard import TargetRejected, is_ip_blocked, parse_target, validate_target


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "fd00:ec2::254",
    "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:7f00:1::",
])
def test_blocked_addresses(ip):
    assert is_ip_blocked(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"])
def test_public_addresses_allowed(ip):
    assert not is_ip_blocked(ip)


@pytest.mark.parametrize("url", [
    "http://localhost", "http://127.0.0.1", "http://0.0.0.0", "http://169.254.169.254/latest/meta-data",
    "http://[::1]/", "http://2130706433/", "http://10.0.0.5", "http://[::ffff:7f00:1]/",
])
def test_internal_targets_rejected(url):
    with pytest.raises(TargetRejected):
        asyncio.run(validate_target(url))


@pytest.mark.parametrize("url", ["ftp://example.com", "file:///etc/passwd", "http://user:pw@example.com",
                                 "http://example.com:22", "", "https://"])
def test_bad_urls_rejected(url):
    with pytest.raises(TargetRejected):
        parse_target(url)


def test_scheme_added_and_fragment_stripped():
    assert parse_target("example.com/a#frag") == "https://example.com/a"
