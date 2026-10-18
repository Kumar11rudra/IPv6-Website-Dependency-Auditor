import dataclasses
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models.db import get_db
from ..models.schemas import HostProbeOut, ResourceOut, ScanOut, ScanRequest
from ..models.tables import HostProbe, MeasurementContext, Resource, Scan
from ..scanner.context import ScanContext
from ..reports.csv_report import build_scan_csv_report
from ..reports.json_report import build_scan_json_report
from ..scanner.dependency_graph import build_graph
from ..scanner.ssrf_guard import TargetRejected, validate_target
from ..services.scan_runner import run_scan

router = APIRouter(prefix="/api")


@router.post("/scan", response_model=ScanOut, status_code=202)
async def create_scan(body: ScanRequest, bg: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        url = await validate_target(body.url)
    except TargetRejected as e:
        raise HTTPException(400, {"error": "TARGET_REJECTED", "detail": str(e)})
    scan = Scan(scan_id=uuid.uuid4().hex[:12], target_url=url, scanner_version=settings.scanner_version)
    db.add(scan)
    db.commit()
    bg.add_task(run_scan, scan.scan_id)
    return scan


def _get_scan(db: Session, scan_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


@router.get("/scan/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    return _get_scan(db, scan_id)


@router.get("/scan/{scan_id}/resources", response_model=list[ResourceOut])
def get_resources(scan_id: str, db: Session = Depends(get_db)):
    _get_scan(db, scan_id)
    return db.scalars(select(Resource).where(Resource.scan_id == scan_id).order_by(Resource.resource_id)).all()


@router.get("/scan/{scan_id}/context")
def get_scan_context(scan_id: str, db: Session = Depends(get_db)):
    _get_scan(db, scan_id)
    row = db.get(MeasurementContext, scan_id)
    if row is None:
        raise HTTPException(404, "measurement context not recorded for this scan")
    data = {f.name: getattr(row, f.name) for f in dataclasses.fields(ScanContext)}
    return ScanContext(**data).display()


@router.get("/scan/{scan_id}/probes", response_model=list[HostProbeOut])
def get_probes(scan_id: str, db: Session = Depends(get_db)):
    _get_scan(db, scan_id)
    return db.scalars(select(HostProbe).where(HostProbe.scan_id == scan_id)
                      .order_by(HostProbe.hostname, HostProbe.port, HostProbe.family)).all()


@router.get("/scan/{scan_id}/graph")
def get_graph(scan_id: str, db: Session = Depends(get_db)):
    _get_scan(db, scan_id)
    resources = [ResourceOut.model_validate(r).model_dump()
                for r in db.scalars(select(Resource).where(Resource.scan_id == scan_id))]
    probes = [HostProbeOut.model_validate(p).model_dump()
             for p in db.scalars(select(HostProbe).where(HostProbe.scan_id == scan_id))]
    return build_graph(resources, probes)


@router.get("/scan/{scan_id}/report/json")
def get_scan_report_json(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    report = build_scan_json_report(db, scan)
    return JSONResponse(content=report, headers={
        "Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'})


@router.get("/scan/{scan_id}/report/csv")
def get_scan_report_csv(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    csv_text = build_scan_csv_report(db, scan)
    return PlainTextResponse(content=csv_text, media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="scan_{scan_id}.csv"'})
