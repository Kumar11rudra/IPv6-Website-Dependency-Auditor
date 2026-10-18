from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import batch, context, scans
from .config import settings
from .middleware import MaxBodySizeMiddleware
from .models.db import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="IPv6 Website & Dependency Readiness Auditor", version=settings.scanner_version, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_request_body_bytes)
app.include_router(scans.router)
app.include_router(context.router)
app.include_router(batch.router)


from fastapi.responses import RedirectResponse, Response


@app.get("/", include_in_schema=False)
@app.head("/", include_in_schema=False)
def root():
    return RedirectResponse(url="http://localhost:5173", status_code=307)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/api/health")
def health():
    return {"status": "ok", "scanner_version": settings.scanner_version}

