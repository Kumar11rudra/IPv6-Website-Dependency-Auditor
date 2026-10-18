"""SSRF protection: reject targets that are not publicly routable.

Checked (a) on the user-supplied URL before a scan is queued and (b) for every
host the browser tries to contact, via Playwright request interception.

Known limitation (documented): a hostname is resolved by this guard and again by
Chromium, so a DNS-rebinding attacker with a very short TTL could in theory
differ between the two lookups. Phase 9 closes the TRUST side of this gap (see
resource_discovery.py's post-hoc remote_ip check); it cannot prevent a single
already-in-flight TCP SYN from reaching a rebound address before that check runs.
Production mitigation: also run the scanner in a VM/namespace whose egress
firewall blocks private ranges, as defense in depth below the application layer.
"""
from __future__ import annotations
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from ..config import settings


class TargetRejected(ValueError):
    """URL is malformed or points somewhere the scanner must not touch."""


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def normalize_ip_literal(host: str) -> str | None:
    """Recognises an IP address literal EVEN IN THE LEGACY, loosely-parsed forms that
    browsers accept (decimal: "2130706433", octal: "017700000001", hex: "0x7f000001",
    and short forms like "127.1"), returning its normalised dotted-quad/IPv6 text, or
    None if the string is not an IP literal in any form and needs real DNS resolution.

    Why this exists: Python's ipaddress.ip_address() is STRICT (RFC-conformant dotted
    quad or IPv6 text only) and rejects every one of the legacy forms above. Chromium's
    own URL parser (WHATWG spec) accepts all of them and will connect directly to the
    address they encode, without any DNS lookup at all. If this guard only trusted
    ip_address() and then fell through to DNS for anything it didn't recognise, a target
    like "http://2130706433/" would look like an unresolvable hostname to US (NXDOMAIN,
    nothing to block) while Chromium connects straight to 127.0.0.1 - a classic SSRF
    bypass (CWE-918).

    On this project's actual deployment target (glibc-based Linux), asyncio's own
    getaddrinfo() HAPPENS to also recognise these forms and already blocks them - verified
    directly during the Phase 9 audit, not assumed. But that protection is an ACCIDENT of
    glibc's particular getaddrinfo behaviour, not anything this codebase explicitly
    guarantees: musl libc (used by Alpine-based containers) has historically differed, and
    nothing stops a future refactor from routing resolution through a library (like
    dnspython, already used elsewhere in this very codebase for the DNS-checking stage)
    that has no such fallback at all. This function makes the protection explicit, correct
    regardless of the underlying libc or resolver library, and independently testable.
    """
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if ":" in host:
        return None  # inet_aton is IPv4-only; a string with colons is not a legacy IPv4 form
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        return None


def is_ip_blocked(ip: str) -> bool:
    """True if loopback/private/link-local/CGNAT/reserved/multicast/etc."""
    addr = ipaddress.ip_address(ip.strip("[]").split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address):
        # Unwrap IPv6 forms that embed an IPv4 address so they can't smuggle one through.
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        elif addr in _NAT64:
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        elif addr.sixtofour is not None:
            addr = addr.sixtofour
    return (not addr.is_global) or addr.is_multicast


def is_allowlisted(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in settings.ssrf_allow_hosts)


def parse_target(raw: str) -> str:
    """Syntactic validation. Returns a normalised http(s) URL or raises TargetRejected."""
    raw = (raw or "").strip()
    if not raw:
        raise TargetRejected("URL is empty")
    if len(raw) > 2048:
        raise TargetRejected("URL is too long")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise TargetRejected(f"Scheme '{parts.scheme}' is not allowed (http/https only)")
    host = parts.hostname
    if not host:
        raise TargetRejected("URL has no hostname")
    if parts.username or parts.password:
        raise TargetRejected("Credentials in URL are not allowed")
    try:
        port = parts.port
    except ValueError:
        raise TargetRejected("Invalid port")
    if port is not None and port not in settings.allowed_ports and not is_allowlisted(host):
        raise TargetRejected(f"Port {port} is not allowed")
    return parts._replace(fragment="").geturl()


async def resolve_addresses(host: str) -> list[str]:
    """All addresses (A + AAAA) for host. Empty list if it does not resolve."""
    host = host.strip("[]")
    literal = normalize_ip_literal(host)
    if literal is not None:
        return [literal]
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), 5)
    except (socket.gaierror, asyncio.TimeoutError, UnicodeError):
        return []
    return sorted({i[4][0] for i in infos})


async def assert_public(host: str) -> None:
    if is_allowlisted(host):
        return
    for ip in await resolve_addresses(host):
        if is_ip_blocked(ip):
            raise TargetRejected(f"{host} resolves to non-public address {ip}")


async def validate_target(raw: str) -> str:
    """Full validation of a user-supplied URL. Unresolvable hosts pass through:
    that is a measurement outcome (DNS failure), not a security problem."""
    url = parse_target(raw)
    await assert_public(urlsplit(url).hostname)
    return url


class HostGuard:
    """Per-scan cache of host -> allowed?, used by browser request interception."""

    def __init__(self) -> None:
        self._cache: dict[str, bool] = {}

    async def allowed(self, host: str) -> bool:
        host = host.lower()
        if host not in self._cache:
            try:
                await assert_public(host)
                self._cache[host] = True
            except TargetRejected:
                self._cache[host] = False
        return self._cache[host]
