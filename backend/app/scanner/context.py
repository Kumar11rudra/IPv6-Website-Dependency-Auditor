"""Measurement context: WHERE and HOW the measurement was taken.

Kept separate from website findings. Anything that cannot be determined is left
as None and rendered "Unknown". Values are never inferred or guessed.
"""
from __future__ import annotations
import asyncio
import ipaddress
import json
import logging
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Awaitable, Callable

import httpx

from ..config import settings
from ..models.tables import utcnow
from .dns_checker import DnsResolver, OK

log = logging.getLogger(__name__)
UNKNOWN = "Unknown"
RESOLV_CONF = "/etc/resolv.conf"
SYSTEMD_RESOLV = "/run/systemd/resolve/resolv.conf"

# Literal IPs: the egress check needs no DNS. Success = a TCP handshake completes.
TCP_TARGETS = {
    4: [("1.1.1.1", 443), ("8.8.8.8", 443)],
    6: [("2606:4700:4700::1111", 443), ("2001:4860:4860::8888", 443)],
}
PUBLIC_IP_URL = "https://api64.ipify.org"  # dual-stack; family is forced by the client


@dataclass
class ScanContext:
    collected_at: str
    resolver_ips: list[str] = field(default_factory=list)
    resolver_upstream_ips: list[str] = field(default_factory=list)
    resolver_source: str | None = None
    resolver_is_local_stub: bool | None = None
    resolver_egress_ip: str | None = None
    scanner_public_ipv4: str | None = None
    scanner_public_ipv6: str | None = None
    ipv4_egress_ok: bool | None = None
    ipv6_egress_ok: bool | None = None
    geo_ip: str | None = None
    geo_country: str | None = None
    geo_region: str | None = None
    geo_city: str | None = None
    geo_org: str | None = None
    geo_source: str | None = None
    warnings: list[str] = field(default_factory=list)

    def db_fields(self) -> dict:
        return asdict(self)

    def display(self) -> dict:
        """API/report form: None / empty -> "Unknown"; False stays False."""
        return {k: (UNKNOWN if v is None or v == "" or v == [] else v) for k, v in asdict(self).items()}


# ---------- resolver detection ----------
def parse_nameservers(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        parts = line.split("#")[0].split(";")[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                ipaddress.ip_address(parts[1].split("%")[0])
                out.append(parts[1])
            except ValueError:
                pass
    return out


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _fill_resolvers(ctx: ScanContext, resolv_conf: str, systemd_resolv: str) -> None:
    text = _read(resolv_conf)
    if text is None:
        return
    ips = parse_nameservers(text)
    if not ips:
        return
    ctx.resolver_ips, ctx.resolver_source = ips, resolv_conf
    ctx.resolver_is_local_stub = any(ipaddress.ip_address(i.split("%")[0]).is_loopback for i in ips)
    if ctx.resolver_is_local_stub:
        up = _read(systemd_resolv)  # real upstreams behind systemd-resolved's 127.0.0.53 stub
        if up:
            ctx.resolver_upstream_ips = parse_nameservers(up)


# ---------- network primitives (injectable for tests) ----------
async def tcp_reachable(host: str, port: int, family: int, timeout: float) -> bool:
    try:
        fam = socket.AF_INET6 if family == 6 else socket.AF_INET
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, family=fam), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    return True


async def http_get_text(url: str, family: int, timeout: float) -> str | None:
    """GET forced over one address family (binding the local address pins the family)."""
    transport = httpx.AsyncHTTPTransport(local_address="::" if family == 6 else "0.0.0.0")
    try:
        async with httpx.AsyncClient(transport=transport, timeout=timeout) as c:
            r = await c.get(url)
            r.raise_for_status()
            return r.text.strip()
    except (httpx.HTTPError, OSError):
        return None


async def whoami_lookup() -> str | None:
    """whoami.akamai.net answers with the address of the recursive resolver that
    contacted Akamai: the resolver's public egress IP as seen from outside."""
    res = await DnsResolver(settings.dns_timeout_s).lookup("whoami.akamai.net", 4)
    return res.addresses[0] if res.status == OK and res.addresses else None


# ---------- geolocation providers ----------
def _parse_ipinfo(d: dict) -> dict | None:
    if d.get("bogon") or d.get("error") or not d.get("country"):
        return None
    return {"country": d.get("country"), "region": d.get("region"), "city": d.get("city"), "org": d.get("org")}


def _parse_ipwhois(d: dict) -> dict | None:
    if d.get("success") is False or not d.get("country_code"):
        return None
    return {"country": d.get("country_code"), "region": d.get("region"), "city": d.get("city"),
            "org": (d.get("connection") or {}).get("org")}


GEO_PROVIDERS = [
    ("ipinfo.io", "https://ipinfo.io/{ip}/json", _parse_ipinfo),
    ("ipwho.is", "https://ipwho.is/{ip}", _parse_ipwhois),
]


def _valid_public_ip(text: str | None, family: int) -> str | None:
    try:
        addr = ipaddress.ip_address((text or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == family and addr.is_global else None


async def _safe(aw: Awaitable):
    try:
        return await aw
    except Exception:  # noqa: BLE001 - context collection must never break a scan
        log.exception("context step failed")
        return None


async def collect_context(*, tcp=tcp_reachable, http_get=http_get_text, whoami=whoami_lookup,
                          resolv_conf: str = RESOLV_CONF, systemd_resolv: str = SYSTEMD_RESOLV,
                          timeout: float = 4.0) -> ScanContext:
    ctx = ScanContext(collected_at=utcnow())
    _fill_resolvers(ctx, resolv_conf, systemd_resolv)

    async def egress(fam: int) -> bool | None:
        try:
            return any(await asyncio.gather(*(tcp(h, p, fam, timeout) for h, p in TCP_TARGETS[fam])))
        except Exception:  # noqa: BLE001
            return None  # could not be tested -> Unknown (not "failed")

    ctx.ipv4_egress_ok, ctx.ipv6_egress_ok, ctx.resolver_egress_ip = await asyncio.gather(
        egress(4), egress(6), _safe(whoami()))

    for fam, ok, attr in ((4, ctx.ipv4_egress_ok, "scanner_public_ipv4"), (6, ctx.ipv6_egress_ok, "scanner_public_ipv6")):
        if ok:
            text = await _safe(http_get(PUBLIC_IP_URL, fam, timeout))
            setattr(ctx, attr, _valid_public_ip(text, fam))

    if ctx.ipv4_egress_ok is False:
        ctx.warnings.append("IPv4 egress unavailable from the scanner host.")
    if ctx.ipv6_egress_ok is False:
        ctx.warnings.append("IPv6 egress unavailable from the scanner host: IPv6 probe results must be "
                            "reported as NOT_TESTED, not as failures of the target.")
    for fam, ok in ((4, ctx.ipv4_egress_ok), (6, ctx.ipv6_egress_ok)):
        if ok is None:
            ctx.warnings.append(f"IPv{fam} egress could not be determined.")

    # Geolocation of the scanner's public IP (approximate; prefer IPv4 databases).
    ip, fam = (ctx.scanner_public_ipv4, 4) if ctx.scanner_public_ipv4 else (ctx.scanner_public_ipv6, 6)
    if not ip:
        ctx.warnings.append("Scanner public IP unknown; geolocation not attempted.")
    else:
        for name, url, parser in GEO_PROVIDERS:
            text = await _safe(http_get(url.format(ip=ip), fam, timeout))
            try:
                geo = parser(json.loads(text)) if text else None
            except (ValueError, AttributeError):
                geo = None
            if geo:
                ctx.geo_ip, ctx.geo_source = ip, name
                ctx.geo_country, ctx.geo_region, ctx.geo_city, ctx.geo_org = (
                    geo["country"], geo["region"], geo["city"], geo["org"])
                break
        else:
            ctx.warnings.append("Geolocation lookup failed; recorded as Unknown.")
    return ctx


_cache: tuple[float, ScanContext] | None = None


async def get_context(force: bool = False) -> ScanContext:
    """Cached (TTL) so a 30-site batch does not hammer third-party lookup APIs."""
    global _cache
    if not force and _cache and time.monotonic() - _cache[0] < settings.context_ttl_s:
        return _cache[1]
    try:
        ctx = await collect_context()
    except Exception:  # noqa: BLE001
        log.exception("context collection failed")
        ctx = ScanContext(collected_at=utcnow(), warnings=["Context collection failed; all values Unknown."])
    _cache = (time.monotonic(), ctx)
    return ctx
