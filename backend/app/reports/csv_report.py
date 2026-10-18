"""CSV report builders. Uses Python's csv module throughout (never manual string
joining/concatenation), so quoting, embedded commas, quotes, and newlines in any field
(a URL, an error message) are escaped correctly per RFC 4180 automatically.
"""
import csv
import io

from sqlalchemy.orm import Session

from ..models.tables import Batch, Scan
from .common import batch_report_data, scan_report_data

# Phase 9: CSV/formula injection (CWE-1236). RFC-4180 escaping (handled by the csv
# module already) protects against breaking the CSV's STRUCTURE, but says nothing
# about how a spreadsheet application INTERPRETS a cell's content once opened. If any
# field starts with =, +, -, or @, Excel/Sheets/LibreOffice may treat the whole cell as
# a formula when a human later opens the exported file - a resource URL, hostname, or
# error message that happens to start with one of these is a GENUINE possibility here,
# since every field in this report ultimately comes from a page the scanner visited,
# not from a source this application controls. The standard mitigation (OWASP): if a
# field's text starts with one of those characters, prefix it with a single quote,
# which every major spreadsheet application treats as "force text" and which does NOT
# change the value a human or a program reading the CSV as data (not opening it in a
# spreadsheet) sees - csv.DictReader round-trips it identically either way, so this
# cannot break anything that treats the file as plain CSV data.
_FORMULA_LEAD_CHARS = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_field(value):
    if isinstance(value, str) and value.startswith(_FORMULA_LEAD_CHARS):
        return "'" + value
    return value


def _sanitize_row(row: dict) -> dict:
    return {k: sanitize_csv_field(v) for k, v in row.items()}

RESOURCE_COLUMNS = [
    "scan_id", "timestamp", "target", "final_url", "hostname", "port", "resource_type",
    "resource_url", "initiator", "load_status", "http_status", "error_text",
    "ipv4_dns_status", "ipv4_tcp_status", "ipv4_tls_status", "ipv4_http_status",
    "ipv4_http_code", "ipv4_verdict", "ipv4_failure_stage", "ipv4_failure_subtype",
    "ipv6_dns_status", "ipv6_tcp_status", "ipv6_tls_status", "ipv6_http_status",
    "ipv6_http_code", "ipv6_verdict", "ipv6_failure_stage", "ipv6_failure_subtype",
    "family_comparison",
]

BATCH_PREFIX_COLUMNS = ["batch_id", "batch_status", "site_index", "site_name", "site_url", "site_status"]


def _resource_to_row(report: dict, r: dict) -> dict:
    row = {
        "scan_id": report["scan_id"], "timestamp": r["timestamp"], "target": report["target"],
        "final_url": report["final_url"], "hostname": r["hostname"], "port": r["port"],
        "resource_type": r["resource_type"], "resource_url": r["url"], "initiator": r["initiator"],
        "load_status": r["load_status"], "http_status": r["http_status"], "error_text": r["error_text"],
        "family_comparison": r["family_comparison"],
    }
    for fam in ("ipv4", "ipv6"):
        block = r[fam]
        row[f"{fam}_dns_status"] = block["dns_status"]
        row[f"{fam}_tcp_status"] = block["tcp_status"]
        row[f"{fam}_tls_status"] = block["tls_status"]
        row[f"{fam}_http_status"] = block["http_stage_status"]
        row[f"{fam}_http_code"] = block["http_code"]
        row[f"{fam}_verdict"] = block["verdict"]
        row[f"{fam}_failure_stage"] = block["failure_stage"]
        row[f"{fam}_failure_subtype"] = block["failure_subtype"]
    return row


def build_scan_csv_report(db: Session, scan: Scan) -> str:
    report = scan_report_data(db, scan)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=RESOURCE_COLUMNS, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    for r in report["resources"]:
        writer.writerow(_sanitize_row(_resource_to_row(report, r)))
    return buf.getvalue()


def build_batch_csv_report(db: Session, batch: Batch) -> str:
    """One row per (site, resource), reusing the exact same per-resource row shape as a
    single-scan CSV so the two never have divergent column semantics - just extra
    leading columns identifying which site each row belongs to."""
    report = batch_report_data(db, batch)
    buf = io.StringIO()
    fieldnames = BATCH_PREFIX_COLUMNS + RESOURCE_COLUMNS
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    for site in report["sites"]:
        site_scan = db.get(Scan, site["scan_id"])  # same session; fetch this site's own resources
        site_report = scan_report_data(db, site_scan)
        prefix = {
            "batch_id": report["batch_id"], "batch_status": report["status"],
            "site_index": site["site_index"], "site_name": site["name"],
            "site_url": site["url"], "site_status": site["status"],
        }
        if not site_report["resources"]:
            writer.writerow(_sanitize_row(prefix))  # site attempted but produced no resources (BLOCKED/SCAN_FAILED/empty)
        for r in site_report["resources"]:
            writer.writerow(_sanitize_row({**prefix, **_resource_to_row(site_report, r)}))
    return buf.getvalue()
