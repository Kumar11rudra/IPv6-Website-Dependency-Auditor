"""Orchestrates one scan. Never raises: every failure ends as a recorded scan status."""
from __future__ import annotations
import asyncio
import logging
from collections import Counter
from urllib.parse import urlsplit

from ..config import settings
from ..models.db import SessionLocal
from ..models.tables import HostProbe, MeasurementContext, Resource, Scan, utcnow
from ..scanner.browser import capture_page
from ..scanner.context import get_context
from ..scanner.dns_checker import DnsResolver
from ..scanner.resource_discovery import normalize
from ..scanner.ssrf_guard import HostGuard, TargetRejected, validate_target
from .probe_service import dns_summary, probe_summary, run_dns_stage, run_family_probes

log = logging.getLogger(__name__)
_sem: asyncio.Semaphore | None = None


def _semaphore() -> asyncio.Semaphore:
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(settings.max_concurrent_scans)
    return _sem


def summarize(rows: list[dict]) -> dict:
    return {
        "resources": len(rows),
        "hosts": len({r["hostname"] for r in rows}),
        "by_type": dict(Counter(r["resource_type"] for r in rows)),
        "by_load_status": dict(Counter(r["load_status"] for r in rows)),
        # Which family Chromium happened to use on a dual-stack host. NOT an IPv6 verdict.
        "browser_connected_family": {
            str(k): v for k, v in Counter(r["remote_family"] for r in rows if r["remote_family"]).items()
        },
        "note": "Discovery, DNS and per-family TCP/TLS/HTTP probing. Dependency graph and readiness score arrive in Phase 4+.",
    }


async def run_scan(scan_id: str) -> None:
    async with _semaphore():
        ctx_task = asyncio.create_task(get_context())  # runs alongside the browser load
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            scan.status, scan.started_at = "RUNNING", utcnow()
            db.commit()
            ctx = None
            try:
                url = await validate_target(scan.target_url)
                cap = await capture_page(url, settings, HostGuard())
                rows = normalize(cap.requests, cap.guard_blocked_urls, cap.redirect_limit_urls)
                summary = summarize(rows)
                problems = [m for m, hit in [
                    (f"navigation error: {cap.nav_error}", cap.nav_error),
                    ("scan deadline reached", cap.deadline_hit),
                    ("resource limit reached", cap.truncated),
                ] if hit]

                probes: list[dict] = []
                try:
                    blocked_hosts = {(urlsplit(u).hostname or "").lower() for u in cap.guard_blocked_urls}
                    probes, host_dns = await run_dns_stage(
                        rows, blocked_hosts, DnsResolver(settings.dns_timeout_s), settings.probe_concurrency,
                        settings.max_hosts_per_scan)
                    summary["dns"] = dns_summary(host_dns)
                    ctx = await ctx_task  # already collected while the browser was loading
                    await run_family_probes(probes, rows, ctx.ipv4_egress_ok, ctx.ipv6_egress_ok, settings)
                    summary["probes"] = probe_summary(probes)
                except Exception as e:  # noqa: BLE001
                    log.exception("DNS/probe stage failed for scan %s", scan_id)
                    problems.append(f"DNS/probe stage failed: {type(e).__name__}")

                for row in rows:
                    db.add(Resource(scan_id=scan_id, **row))
                for p in probes:
                    db.add(HostProbe(scan_id=scan_id, **p))
                scan.final_url, scan.truncated, scan.summary = cap.final_url, cap.truncated, summary

                if not rows:
                    scan.status, scan.error = "SCAN_FAILED", "; ".join(problems) or "No resources captured"
                elif problems:
                    scan.status, scan.error = "PARTIAL", "; ".join(problems)
                else:
                    scan.status = "COMPLETED"
            except TargetRejected as e:
                scan.status, scan.error = "BLOCKED", str(e)
            except Exception as e:  # noqa: BLE001 - a scan must never crash the service
                log.exception("scan %s failed", scan_id)
                scan.status, scan.error = "SCAN_FAILED", f"{type(e).__name__}: {e}"[:500]

            try:  # context is stored even for failed scans; get_context() never raises
                db.add(MeasurementContext(scan_id=scan_id, **(ctx or await ctx_task).db_fields()))
            except Exception:  # noqa: BLE001
                log.exception("could not store measurement context for %s", scan_id)
            scan.finished_at = utcnow()
            db.commit()
