"""JSON report builders. Thin wrappers over reports/common.py - all the actual data
assembly, redaction, and "Unknown" handling lives there so JSON and CSV never diverge."""
from sqlalchemy.orm import Session

from ..models.tables import Batch, Scan
from .common import batch_report_data, scan_report_data


def build_scan_json_report(db: Session, scan: Scan) -> dict:
    return scan_report_data(db, scan)


def build_batch_json_report(db: Session, batch: Batch) -> dict:
    return batch_report_data(db, batch)
