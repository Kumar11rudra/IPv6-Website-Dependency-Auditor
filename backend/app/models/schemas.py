from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..reports.redact import redact_text, redact_url

# Phase 9 finding: Phase 7's redaction (reports/redact.py) was only ever wired into the
# /report/json and /report/csv endpoints. Every OTHER live, client-facing endpoint -
# /scan/{id}, /scan/{id}/resources, /scan/{id}/graph, /batch-scan/{id}/sites - returned
# raw, unredacted url/error fields, which the dashboard displays directly. A credential
# or token embedded in a discovered resource's URL (e.g. a tracking pixel's query
# string) was therefore fully visible in the live UI even though it was already hidden
# from exported reports - an inconsistency, not a deliberate scope boundary. Fixed here,
# once, at the serialization layer: these validators apply the SAME already-tested
# redact_url/redact_text functions reports already use, so there is only ever one
# redaction implementation. The database itself is never touched - internal code
# (including the controlled-site's own detection tests, which call scanner functions
# directly) still sees the raw, original values; only data leaving the API is redacted.


class ScanRequest(BaseModel):
    url: str


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    scan_id: str
    target_url: str
    final_url: str | None
    status: str
    error: str | None
    scanner_version: str
    batch_id: str | None
    truncated: bool
    created_at: str
    started_at: str | None
    finished_at: str | None
    summary: dict | None

    _r_target = field_validator("target_url")(lambda v: redact_url(v))
    _r_final = field_validator("final_url")(lambda v: redact_url(v))
    _r_error = field_validator("error")(lambda v: redact_text(v))


class ResourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    resource_id: str
    parent_resource_id: str | None
    parent_inferred: bool
    url: str
    hostname: str
    port: int
    resource_type: str
    initiator: str
    protocol: str | None
    http_status: int | None
    load_status: str
    error_text: str | None
    remote_ip: str | None
    remote_family: int | None
    timestamp: str | None
    ipv4_addresses: list
    ipv6_addresses: list

    _r_url = field_validator("url")(lambda v: redact_url(v))
    _r_err = field_validator("error_text")(lambda v: redact_text(v))


class HostProbeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    hostname: str
    port: int
    family: int
    dns_status: str
    dns_addresses: list
    dns_detail: str | None
    canonical_name: str | None
    resolver_used: str | None
    dns_ms: int | None
    tcp_status: str
    tls_status: str
    http_stage_status: str
    http_code: int | None
    failure_stage: str | None
    failure_subtype: str | None
    error_detail: str | None
    probe_scheme: str | None
    probe_path: str | None
    verdict: str | None
    family_comparison: str | None
    connected_address: str | None
    addresses_tested: int
    addresses_reachable: int
    tcp_ms: int | None
    tls_ms: int | None
    http_ms: int | None
    tls_version: str | None

    _r_detail = field_validator("error_detail")(lambda v: redact_text(v))
    _r_dns_detail = field_validator("dns_detail")(lambda v: redact_text(v))


class BatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    batch_id: str
    status: str
    total: int
    source: str
    scanner_version: str
    error: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None
    # Computed, not stored columns:
    completed: int
    summary: dict

    _r_error = field_validator("error")(lambda v: redact_text(v))


class BatchSiteOut(BaseModel):
    site_index: int
    name: str
    url: str
    scan_id: str
    status: str
    error: str | None = None

    _r_url = field_validator("url")(lambda v: redact_url(v))
    _r_error = field_validator("error")(lambda v: redact_text(v))


class SiteInput(BaseModel):
    """One entry in a custom batch site list. Phase 9: replaces a bare `dict` with
    real, framework-level validation (length limits, required url) so malformed input
    is rejected by FastAPI/Pydantic with a clear 422 before any application code runs,
    rather than relying entirely on batch_runner.py's own manual checks."""
    name: str | None = Field(default=None, max_length=255)
    url: str = Field(min_length=1, max_length=2048)


class BatchScanRequest(BaseModel):
    # None = load the default sites.json. Capped well above batch_max_sites (enforced
    # again, authoritatively, in build_site_list) so an oversized list is rejected by
    # Pydantic's own validation - before the request body is even fully processed -
    # rather than only after building Python objects for every entry.
    sites: list[SiteInput] | None = Field(default=None, max_length=500)
    include_controlled: bool = True
