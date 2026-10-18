"""Host-level probe records. Phase 2: DNS stage only (A and AAAA per host).

tcp/tls/http stages stay NOT_TESTED until Phase 3. A DNS answer is recorded as
"advertised in DNS", never as reachability.
"""
from __future__ import annotations
import asyncio
import ipaddress

from ..scanner import dns_checker as d
from ..scanner.dns_checker import DnsResolver, DnsResult
from ..scanner.ssrf_guard import is_allowlisted, is_ip_blocked


def _literal(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _enforce_public(host: str, res: dict[int, DnsResult]) -> None:
    if is_allowlisted(host):
        return
    for r in res.values():
        if r.status in (d.OK, d.LITERAL) and any(is_ip_blocked(a) for a in r.addresses):
            r.status, r.detail = d.BLOCKED, "Resolves to a non-public address; not probed (SSRF policy)"


async def run_dns_stage(rows: list[dict], guard_blocked_hosts: set[str], resolver: DnsResolver,
                        concurrency: int = 10, max_hosts: int | None = None
                        ) -> tuple[list[dict], dict[str, dict[int, DnsResult]]]:
    """Resolve every distinct hostname once per family. Mutates rows' ipv4/ipv6_addresses
    (addresses ADVERTISED in DNS). Returns (host_probe rows, per-host results).

    Phase 9: max_hosts caps how many DISTINCT hosts actually get DNS/TCP/TLS/HTTP work
    done for them. Without this, a page with resources spread across hundreds of
    distinct hosts (whether by design or as a crude denial-of-service against the
    scanner itself) could trigger unboundedly many outbound DNS lookups and
    connections per scan - max_resources (Phase 1) already bounds total RESOURCES, but
    says nothing about how many distinct HOSTS those resources might span. Hosts
    beyond the cap are recorded as HOST_LIMIT_EXCEEDED (visibly "not tested because of
    a limit", not silently dropped as if they were never discovered) rather than
    probed. Which hosts are kept is based on DISCOVERY order (first seen while
    iterating captured resources, i.e. roughly page-load order) so the hosts kept are
    the ones that mattered earliest to the page, not an arbitrary alphabetical cut -
    the final output ordering below is unaffected and stays alphabetical as before.
    """
    ports: dict[str, set[int]] = {}
    discovery_order: list[str] = []
    for r in rows:
        host = r["hostname"]
        if host not in ports:
            discovery_order.append(host)
        ports.setdefault(host, set()).add(r["port"])

    if max_hosts is not None and len(discovery_order) > max_hosts:
        probed_hosts = set(discovery_order[:max_hosts])
    else:
        probed_hosts = set(ports)

    sem = asyncio.Semaphore(concurrency)

    async def resolve(host: str) -> tuple[str, dict[int, DnsResult]]:
        if host not in probed_hosts:
            detail = f"Scan already reached the configured host limit ({max_hosts}); this host was not tested"
            res = {f: DnsResult(f, d.HOST_LIMIT_EXCEEDED, [], detail) for f in (4, 6)}
            return host, res
        lit = _literal(host)
        if lit is not None:
            other = 6 if lit.version == 4 else 4
            res = {lit.version: DnsResult(lit.version, d.LITERAL, [str(lit)], "Hostname is an IP literal; no DNS lookup"),
                   other: DnsResult(other, d.NOT_APPLICABLE, [], f"Host is an IPv{lit.version} literal; IPv{other} cannot be tested")}
        elif host in guard_blocked_hosts:
            res = {f: DnsResult(f, d.BLOCKED, [], "Blocked by scanner SSRF guard") for f in (4, 6)}
        else:
            async with sem:
                r4, r6 = await asyncio.gather(resolver.lookup(host, 4), resolver.lookup(host, 6))
            res = {4: r4, 6: r6}
        _enforce_public(host, res)
        return host, res

    host_dns = dict(await asyncio.gather(*(resolve(h) for h in sorted(ports))))

    for r in rows:
        res = host_dns[r["hostname"]]
        usable = (d.OK, d.LITERAL)
        r["ipv4_addresses"] = res[4].addresses if res[4].status in usable else []
        r["ipv6_addresses"] = res[6].addresses if res[6].status in usable else []

    probes = []
    for host in sorted(ports):
        for port in sorted(ports[host]):
            for fam in (4, 6):
                r = host_dns[host][fam]
                probes.append({
                    "hostname": host, "port": port, "family": fam, "dns_status": r.status,
                    "dns_addresses": r.addresses, "dns_detail": r.detail, "canonical_name": r.canonical_name,
                    "resolver_used": r.resolver_used, "dns_ms": r.elapsed_ms,
                })
    return probes, host_dns


def dns_summary(host_dns: dict[str, dict[int, DnsResult]]) -> dict:
    def count(fam: int, *statuses: str) -> int:
        return sum(1 for res in host_dns.values() if res[fam].status in statuses)

    return {
        "hosts": len(host_dns),
        "hosts_with_a_record": count(4, d.OK, d.LITERAL),
        "hosts_advertising_aaaa": count(6, d.OK, d.LITERAL),
        "aaaa_no_record": count(6, d.NO_RECORD),
        "aaaa_lookup_errors": count(6, d.NXDOMAIN, d.TIMEOUT, d.RESOLUTION_ERROR),
        "blocked": count(4, d.BLOCKED),
        "host_limit_exceeded": count(4, d.HOST_LIMIT_EXCEEDED),
        "note": "DNS availability only. An AAAA record means IPv6 is advertised, not that it works.",
    }


# ---------------------------------------------------------------- Phase 3: connectivity stages
import re as _re
from collections import Counter
from urllib.parse import urlsplit as _urlsplit

from ..scanner import classifier
from ..scanner.family_probe import probe_family


def _probe_path(url: str) -> str:
    path = _urlsplit(url).path or "/"          # query string dropped: may carry tokens
    return path if _re.fullmatch(r"/[!-~]*", path) else "/"


async def run_family_probes(probes: list[dict], rows: list[dict], ipv4_ok: bool | None, ipv6_ok: bool | None,
                            cfg, *, probe_fn=probe_family) -> None:
    """Run TCP/TLS/HTTP for every (host, port, family) row and classify it. Mutates `probes`.
    One request per (host, port, family), not per resource, to stay polite to third parties."""
    meta: dict[tuple[str, int], dict] = {}
    for r in rows:
        meta.setdefault((r["hostname"], r["port"]), {"scheme": r["scheme"], "path": _probe_path(r["url"])})
    sem = asyncio.Semaphore(cfg.probe_concurrency)

    async def one(p: dict) -> None:
        m = meta[(p["hostname"], p["port"])]
        async with sem:
            try:
                res = await probe_fn(
                    p["hostname"], p["port"], p["family"], scheme=m["scheme"], path=m["path"],
                    dns_status=p["dns_status"], dns_detail=p["dns_detail"], addresses=p["dns_addresses"],
                    egress_ok=ipv4_ok if p["family"] == 4 else ipv6_ok, cfg=cfg)
            except Exception as e:  # noqa: BLE001 - one bad probe must not lose the rest
                res = {"verdict": "SCAN_FAILED", "error_detail": f"{type(e).__name__}: {e}"[:300]}
        p.update(res)

    await asyncio.gather(*(one(p) for p in probes))

    by_pair: dict[tuple[str, int], dict[int, dict]] = {}
    for p in probes:
        by_pair.setdefault((p["hostname"], p["port"]), {})[p["family"]] = p
    for pair in by_pair.values():
        if 4 in pair and 6 in pair:
            cmp = classifier.compare(pair[4].get("verdict") or "NOT_TESTED", pair[6].get("verdict") or "NOT_TESTED")
            pair[4]["family_comparison"] = pair[6]["family_comparison"] = cmp


def probe_summary(probes: list[dict]) -> dict:
    """Host:port-level counts (NOT resource-level; the readiness score is a later step)."""
    by_family = {f"ipv{f}": dict(Counter(p.get("verdict") for p in probes if p["family"] == f)) for f in (4, 6)}
    comparison = dict(Counter(p.get("family_comparison") for p in probes if p["family"] == 6))
    return {
        "unit": "host:port pairs",
        "by_family": by_family,
        "ipv4_vs_ipv6": comparison,
        "note": ("IPV6_BROKEN = works over IPv4 but fails over IPv6. NOT_TESTED = the scanner could not test that "
                 "family (e.g. no IPv6 egress); it is not a failure of the target."),
    }
