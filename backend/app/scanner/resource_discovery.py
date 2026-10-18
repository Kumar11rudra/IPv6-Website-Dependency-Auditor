"""Normalise raw CDP records into resource rows with parent links (the graph's edges)."""
from __future__ import annotations
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .browser import RawRequest
from .ssrf_guard import is_allowlisted, is_ip_blocked

TYPE_MAP = {
    "Document": "document", "Stylesheet": "stylesheet", "Script": "script", "Image": "image",
    "Font": "font", "XHR": "xhr", "Fetch": "fetch", "Media": "media", "Manifest": "manifest",
    "TextTrack": "texttrack", "WebSocket": "websocket", "Ping": "ping", "Prefetch": "prefetch",
    "EventSource": "eventsource", "Other": "other",
}


def _nofrag(url: str) -> str:
    return url.split("#", 1)[0]


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z") if ts else None


def _load_status(r: RawRequest, guard_blocked: set[str], redirect_limited: set[str]) -> tuple[str, str | None]:
    if r.url in guard_blocked:
        return "BLOCKED", "Blocked by scanner SSRF guard (non-public address)"
    if r.url in redirect_limited:
        return "BLOCKED", "Blocked: redirect chain exceeded the configured limit (resource-exhaustion guard)"
    if r.failed:
        if r.blocked_reason or (r.error_text or "").endswith("ERR_BLOCKED_BY_CLIENT"):
            return "BLOCKED", r.error_text or r.blocked_reason
        return "FAILED", r.error_text
    if r.status is not None:
        return "LOADED", None
    return "INCOMPLETE", "No response before the scan ended"


def _rebinding_override(hostname: str, remote_ip: str | None, status: str,
                        err: str | None) -> tuple[str, str | None]:
    """Post-hoc check, independent of the pre-flight SSRF guard: the guard resolves a
    hostname itself and only then lets Chromium's OWN, SEPARATE resolution proceed, which
    is a real (if narrow) DNS-rebinding TOCTOU window - an attacker with a very low-TTL
    record could serve a public address to our guard's lookup and a private one to
    Chromium's. This does not stop a single already-in-flight connection attempt (that
    gap needs an egress firewall below this application, as documented in ssrf_guard.py),
    but it DOES stop that connection's result from ever being trusted, displayed, or
    reported as a legitimate finding: whatever address the browser actually reports via
    CDP's remoteIPAddress is checked again, here, after the fact, and forcibly
    reclassified as BLOCKED if it turns out to be private - closing the "confused deputy"
    half of the rebinding risk even though the network-level SYN cannot be un-sent."""
    if not remote_ip or is_allowlisted(hostname):
        return status, err
    try:
        blocked = is_ip_blocked(remote_ip)
    except ValueError:
        return status, err  # not a parseable address string; nothing to override
    if blocked and status != "BLOCKED":
        return "BLOCKED", f"Connected address {remote_ip} is non-public (checked post-connection; possible DNS rebinding)"
    return status, err


def normalize(raw: list[RawRequest], guard_blocked: set[str] | None = None,
             redirect_limited: set[str] | None = None) -> list[dict]:
    guard_blocked = guard_blocked or set()
    redirect_limited = redirect_limited or set()
    # CORS preflights are browser plumbing, not page resources.
    raw = [r for r in raw if r.cdp_type != "Preflight"]
    main_frame = next((r.frame_id for r in raw if r.cdp_type == "Document"), None)

    rows: list[dict] = []
    key_to_id: dict[str, str] = {}
    url_to_id: dict[str, str] = {}
    root_id = "r0001"

    for idx, r in enumerate(raw):
        rid = f"r{idx + 1:04d}"
        parts = urlsplit(r.url)
        port = parts.port or (443 if parts.scheme == "https" else 80)

        if idx == 0:
            parent, inferred, initiator = None, False, "root"
        elif r.redirected_from and r.redirected_from in key_to_id:
            parent, inferred, initiator = key_to_id[r.redirected_from], False, "redirect"
        else:
            initiator = r.initiator_type or "unknown"
            parent = url_to_id.get(_nofrag(r.initiator_url)) if r.initiator_url else None
            inferred = parent is None
            if parent is None:
                parent = root_id  # attach to the document; graph labels this edge "inferred"

        rtype = TYPE_MAP.get(r.cdp_type, "other")
        if rtype == "document" and idx > 0 and r.frame_id != main_frame:
            rtype = "iframe"

        status, err = _load_status(r, guard_blocked, redirect_limited)
        family = None
        if r.remote_ip:
            try:
                family = ipaddress.ip_address(r.remote_ip).version
            except ValueError:
                pass
        hostname = (parts.hostname or "").lower()
        status, err = _rebinding_override(hostname, r.remote_ip, status, err)

        rows.append({
            "resource_id": rid,
            "parent_resource_id": parent,
            "parent_inferred": inferred,
            "url": r.url,
            "hostname": hostname,
            "port": port,
            "scheme": parts.scheme,
            "resource_type": rtype,
            "initiator": initiator,
            "initiator_url": r.initiator_url,
            "protocol": r.protocol,
            "http_status": r.status,
            "load_status": status,
            "error_text": err,
            "remote_ip": r.remote_ip,
            "remote_family": family,
            "timestamp": _iso(r.wall_time),
            "ipv4_addresses": [],   # filled by the DNS stage (Phase 2)
            "ipv6_addresses": [],
        })
        key_to_id[r.key] = rid
        url_to_id[_nofrag(r.url)] = rid
    return rows
