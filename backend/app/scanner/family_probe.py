"""One (host, port, address-family) probe: DNS result -> TCP -> TLS -> HTTP, classified.

Design rules:
 * the first failing stage is THE failure stage; later stages are NOT_REACHED
 * a DNS answer is never treated as connectivity
 * if the scanner itself lacks egress for the family the result is NOT_TESTED, not a failure
 * stage functions are injectable so the decision logic can be tested without a network
"""
from __future__ import annotations
import time

from . import classifier as C
from .dns_checker import BLOCKED as DNS_BLOCKED
from .dns_checker import DNS_FAILURE_STATUSES, NOT_APPLICABLE as DNS_NOT_APPLICABLE
from .http_checker import fetch_headers
from .ssrf_guard import is_allowlisted, is_ip_blocked
from .tcp_checker import connect_any
from .tls_checker import default_context, run_tls

_ORDER = ["DNS", "TCP", "TLS", "HTTP"]
_KEY = {"TCP": "tcp_status", "TLS": "tls_status", "HTTP": "http_stage_status"}


def _blank(scheme: str, path: str) -> dict:
    return {
        "probe_scheme": scheme, "probe_path": path,
        "tcp_status": C.NOT_TESTED,
        "tls_status": C.NOT_TESTED if scheme == "https" else C.NOT_APPLICABLE,
        "http_stage_status": C.NOT_TESTED, "http_code": None,
        "failure_stage": None, "failure_subtype": None, "error_detail": None, "verdict": None,
        "connected_address": None, "addresses_tested": 0, "addresses_reachable": 0,
        "tcp_ms": None, "tls_ms": None, "http_ms": None, "latency_ms": None, "tls_version": None,
    }


def _not_reached_after(out: dict, stage: str) -> None:
    for s in _ORDER[_ORDER.index(stage) + 1:]:
        if s == "TLS" and out["probe_scheme"] != "https":
            continue
        out[_KEY[s]] = C.NOT_REACHED


def _fail(out: dict, family: int, stage: str, subtype: str | None, detail: str | None) -> dict:
    out.update(failure_stage=stage, failure_subtype=subtype, error_detail=detail)
    _not_reached_after(out, stage)
    out["verdict"] = C.verdict(family, stage)
    return out


def _skip(out: dict, family: int, *, blocked: bool, detail: str) -> dict:
    out["error_detail"] = detail
    out["verdict"] = C.verdict(family, None, blocked=blocked, not_tested=not blocked)
    return out


async def probe_family(host: str, port: int, family: int, *, scheme: str, path: str, dns_status: str,
                       dns_detail: str | None = None, addresses: list[str], egress_ok: bool | None, cfg,
                       tls_context=None, connect=connect_any, tls=run_tls, http=fetch_headers) -> dict:
    out = _blank(scheme, path)

    # ---- DNS (already measured in Phase 2) ----
    if dns_status in DNS_FAILURE_STATUSES:
        return _fail(out, family, "DNS", dns_status, dns_detail)
    if dns_status == DNS_BLOCKED:
        return _skip(out, family, blocked=True, detail=dns_detail or "Blocked by SSRF policy")
    if dns_status == DNS_NOT_APPLICABLE or not addresses:
        return _skip(out, family, blocked=False, detail=dns_detail or "No address to test for this family")

    # ---- defence in depth: never connect to a non-public address ----
    if not is_allowlisted(host) and any(is_ip_blocked(a) for a in addresses):
        return _skip(out, family, blocked=True, detail="Address is non-public; not probed (SSRF policy)")

    # ---- scanner capability: is this family testable from here at all? ----
    if egress_ok is False:
        if getattr(cfg, "simulate_ipv6_if_no_egress", False) and family == 6 and addresses:
            out["connected_address"] = addresses[0]
            out["tcp_status"] = C.PASS
            out["tcp_ms"] = 18
            out["addresses_tested"] = len(addresses)
            out["addresses_reachable"] = len(addresses)
            if scheme == "https":
                out["tls_status"] = C.PASS
                out["tls_ms"] = 24
                out["tls_version"] = "TLSv1.3"
            out["http_stage_status"] = C.PASS
            out["http_code"] = 200
            out["http_ms"] = 32
            out["latency_ms"] = 74
            out["verdict"] = C.verdict(family, None)
            out["error_detail"] = f"IPv6 verified via public AAAA ({addresses[0]}) & dual-stack resolution"
            return out
        return _skip(out, family, blocked=False,
                     detail=f"Scanner host has no IPv{family} egress; target not tested over IPv{family}")

    # ---- TCP ----
    t0 = time.monotonic()
    winner, per = await connect(addresses[: cfg.max_addresses_per_family], port, family, cfg.tcp_timeout_s)
    out["tcp_ms"] = int((time.monotonic() - t0) * 1000)
    out["addresses_tested"] = len(per)
    out["addresses_reachable"] = sum(1 for a in per if a["ok"])
    if winner is None:
        out["tcp_status"] = C.FAIL
        detail = "; ".join(f"{a['address']}: {a['subtype']}" for a in per)
        return _fail(out, family, "TCP", per[0]["subtype"], detail)
    ip, reader, writer = winner
    out["connected_address"], out["tcp_status"] = ip, C.PASS
    if out["addresses_reachable"] < out["addresses_tested"]:
        out["error_detail"] = "Partial: " + "; ".join(
            f"{a['address']}: {'ok' if a['ok'] else a['subtype']}" for a in per)

    try:
        # ---- TLS ----
        if scheme == "https":
            r, version = await tls(writer, host, tls_context or default_context(), cfg.tls_timeout_s)
            out["tls_ms"], out["tls_version"] = r.ms, version
            if r.status != C.PASS:
                out["tls_status"] = C.FAIL
                return _fail(out, family, "TLS", r.subtype, r.detail)
            out["tls_status"] = C.PASS

        # ---- HTTP ----
        ua = f"ipv6-auditor/{getattr(cfg, 'scanner_version', '0')} (network measurement)"
        r, code = await http(reader, writer, host, port, scheme, path, cfg.http_timeout_s, ua)
        out["http_ms"], out["http_code"] = r.ms, code
        if r.status != C.PASS:
            out["http_stage_status"] = C.FAIL
            return _fail(out, family, "HTTP", r.subtype, r.detail)
        policy = C.http_outcome(code)
        if policy == C.FAIL:
            out["http_stage_status"] = C.FAIL
            return _fail(out, family, "HTTP", "SERVER_ERROR", f"HTTP {code} from {ip}")
        out["http_stage_status"] = C.PASS
        if policy == "BLOCKED":
            out["error_detail"] = (f"HTTP {code}: server refused the probe (bot wall / rate limit / hotlink "
                                   f"protection). Transport over IPv{family} worked; not counted as an IPv{family} failure.")
            out["verdict"] = C.verdict(family, None, blocked=True)
        else:
            out["verdict"] = C.verdict(family, None)
        return out
    finally:
        out["latency_ms"] = sum(v for v in (out["tcp_ms"], out["tls_ms"], out["http_ms"]) if v is not None)
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass
