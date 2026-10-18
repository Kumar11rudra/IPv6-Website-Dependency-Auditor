"""Shared data assembly for both JSON and CSV reports, and for both single-scan and
batch reports. Pure read-side: queries existing Phase 1-6 tables, applies redaction
(reports/redact.py), and returns plain dict/list structures. Never writes to the
database and never touches scanning/probing/classification logic or its stored data.
"""
from __future__ import annotations
import dataclasses
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.tables import Batch, BatchSite, HostProbe, MeasurementContext, Resource, Scan
from ..scanner.context import ScanContext
from .redact import redact_text, redact_url

STAGE_FIELDS = ("dns_status", "tcp_status", "tls_status", "http_stage_status",
               "http_code", "verdict", "failure_stage", "failure_subtype")

EMPTY_FAMILY_BLOCK = {
    "dns_status": "NOT_TESTED", "tcp_status": "NOT_TESTED", "tls_status": "NOT_TESTED",
    "http_stage_status": "NOT_TESTED", "http_code": None, "verdict": "NOT_TESTED",
    "failure_stage": None, "failure_subtype": None,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def context_block(db: Session, scan_id: str) -> dict:
    """Same Unknown-for-missing semantics as the live GET /api/scan/{id}/context
    endpoint (scanner/context.py's ScanContext.display()) - one definition of "Unknown"
    used everywhere in the app, not a second one invented for reports."""
    row = db.get(MeasurementContext, scan_id)
    if row is None:
        return ScanContext(collected_at=None).display()  # scan never got far enough to collect context
    data = {f.name: getattr(row, f.name) for f in dataclasses.fields(ScanContext)}
    return ScanContext(**data).display()


def _family_block(probe: HostProbe | None) -> dict:
    if probe is None:
        return dict(EMPTY_FAMILY_BLOCK)
    return {k: getattr(probe, k) for k in STAGE_FIELDS}


def probes_by_host(db: Session, scan_id: str) -> dict[tuple[str, int], dict[int, HostProbe]]:
    by_host: dict[tuple[str, int], dict[int, HostProbe]] = {}
    for p in db.scalars(select(HostProbe).where(HostProbe.scan_id == scan_id)):
        by_host.setdefault((p.hostname, p.port), {})[p.family] = p
    return by_host


def resource_rows(db: Session, scan_id: str) -> list[dict]:
    """One row per discovered Resource - NOT deduplicated by URL or hostname. If the
    browser genuinely made the same request twice (e.g. a retry), both appear: merging
    them would hide a real finding (first attempt failed, retry succeeded, say)."""
    by_host = probes_by_host(db, scan_id)
    rows = []
    for r in db.scalars(select(Resource).where(Resource.scan_id == scan_id).order_by(Resource.resource_id)):
        host_probes = by_host.get((r.hostname, r.port), {})
        ipv4 = _family_block(host_probes.get(4))
        ipv6 = _family_block(host_probes.get(6))
        comparison = host_probes.get(4).family_comparison if host_probes.get(4) else (
            host_probes.get(6).family_comparison if host_probes.get(6) else None)
        rows.append({
            "resource_id": r.resource_id,
            "parent_resource_id": r.parent_resource_id,
            "url": redact_url(r.url),
            "hostname": r.hostname,
            "port": r.port,
            "resource_type": r.resource_type,
            "initiator": r.initiator,
            "load_status": r.load_status,
            "error_text": redact_text(r.error_text),
            "http_status": r.http_status,
            "timestamp": r.timestamp,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "family_comparison": comparison,
        })
    return rows


def scan_report_data(db: Session, scan: Scan) -> dict:
    return {
        "report_type": "scan",
        "generated_at": now_iso(),
        "scanner_version": scan.scanner_version,
        "scan_id": scan.scan_id,
        "batch_id": scan.batch_id,
        "target": redact_url(scan.target_url),
        "final_url": redact_url(scan.final_url),
        "status": scan.status,
        "error": redact_text(scan.error),
        "truncated": scan.truncated,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "measurement_context": context_block(db, scan.scan_id),
        "summary": scan.summary or {},
        "resources": resource_rows(db, scan.scan_id),
    }


def batch_report_data(db: Session, batch: Batch) -> dict:
    """Per-site SUMMARY only (status, error, that site's own scan.summary counts) -
    not a full resource dump for every site, to keep a 30-site report a sane size. Full
    per-resource detail for any one site remains available via its own scan_id through
    GET /api/scan/{scan_id}/report/json|csv - every scan_id here is an ordinary one."""
    rows = db.execute(
        select(BatchSite, Scan).join(Scan, Scan.scan_id == BatchSite.scan_id)
        .where(BatchSite.batch_id == batch.batch_id).order_by(BatchSite.site_index)
    ).all()
    by_status: dict[str, int] = {}
    sites = []
    for bs, scan in rows:
        by_status[scan.status] = by_status.get(scan.status, 0) + 1
        sites.append({
            "site_index": bs.site_index,
            "name": bs.name,
            "url": redact_url(bs.url),
            "scan_id": scan.scan_id,
            "status": scan.status,
            "error": redact_text(scan.error),
            "scan_summary": scan.summary or {},
        })
    return {
        "report_type": "batch",
        "generated_at": now_iso(),
        "scanner_version": batch.scanner_version,
        "batch_id": batch.batch_id,
        "status": batch.status,
        "source": batch.source,
        "total": batch.total,
        "created_at": batch.created_at,
        "started_at": batch.started_at,
        "finished_at": batch.finished_at,
        "summary": {"total": len(rows), "completed": sum(by_status.values()), "by_status": by_status},
        "sites": sites,
    }
