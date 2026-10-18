import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models.db import get_db
from ..models.schemas import BatchOut, BatchScanRequest, BatchSiteOut
from ..models.tables import Batch, BatchSite, Scan
from ..reports.csv_report import build_batch_csv_report
from ..reports.json_report import build_batch_json_report
from ..services.batch_runner import SitesConfigError, batch_progress, build_site_list, run_batch

router = APIRouter(prefix="/api")


def _serialize(db: Session, batch: Batch) -> dict:
    progress = batch_progress(db, batch.batch_id)
    return {**{c.name: getattr(batch, c.name) for c in Batch.__table__.columns},
            "completed": progress["completed"], "summary": progress}


@router.post("/batch-scan", response_model=BatchOut, status_code=202)
def create_batch(body: BatchScanRequest, bg: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        # SiteInput (Pydantic) -> plain dicts: build_site_list's own contract and
        # batch_runner.py's behavior are unchanged by Phase 9's input-validation
        # tightening (SiteInput.url is required, so "url" is always present here).
        custom_sites = [s.model_dump() for s in body.sites] if body.sites is not None else None
        sites, source = build_site_list(custom_sites, body.include_controlled)
    except SitesConfigError as e:
        raise HTTPException(500, {"error": "SITES_CONFIG_ERROR", "detail": str(e)})
    except ValueError as e:
        raise HTTPException(400, {"error": "INVALID_BATCH_REQUEST", "detail": str(e)})

    batch = Batch(batch_id=uuid.uuid4().hex[:12], total=len(sites), source=source,
                  scanner_version=settings.scanner_version)
    db.add(batch)
    db.commit()
    bg.add_task(run_batch, batch.batch_id, sites)
    return _serialize(db, batch)


def _get_batch(db: Session, batch_id: str) -> Batch:
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise HTTPException(404, "batch not found")
    return batch


@router.get("/batch-scan/{batch_id}", response_model=BatchOut)
def get_batch(batch_id: str, db: Session = Depends(get_db)):
    return _serialize(db, _get_batch(db, batch_id))


@router.get("/batch-scan/{batch_id}/sites", response_model=list[BatchSiteOut])
def get_batch_sites(batch_id: str, db: Session = Depends(get_db)):
    _get_batch(db, batch_id)
    rows = db.execute(
        select(BatchSite, Scan.status, Scan.error)
        .join(Scan, Scan.scan_id == BatchSite.scan_id)
        .where(BatchSite.batch_id == batch_id)
        .order_by(BatchSite.site_index)
    ).all()
    return [BatchSiteOut(site_index=bs.site_index, name=bs.name, url=bs.url, scan_id=bs.scan_id,
                         status=status, error=error) for bs, status, error in rows]


@router.get("/batch-scan/{batch_id}/report/json")
def get_batch_report_json(batch_id: str, db: Session = Depends(get_db)):
    batch = _get_batch(db, batch_id)
    report = build_batch_json_report(db, batch)
    return JSONResponse(content=report, headers={
        "Content-Disposition": f'attachment; filename="batch_{batch_id}.json"'})


@router.get("/batch-scan/{batch_id}/report/csv")
def get_batch_report_csv(batch_id: str, db: Session = Depends(get_db)):
    batch = _get_batch(db, batch_id)
    csv_text = build_batch_csv_report(db, batch)
    return PlainTextResponse(content=csv_text, media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="batch_{batch_id}.csv"'})
