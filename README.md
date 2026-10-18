# IPv6 Website & Dependency Readiness Auditor (AIORI-3 PS-027)

Loads a page in a real browser (Playwright/Chromium + CDP), discovers every resource it requests,
and (from Phase 2) probes each host separately over IPv4 and IPv6 through DNS -> TCP -> TLS -> HTTP.
An AAAA record alone is never treated as proof of IPv6 readiness.

**Status: Phase 9 complete** (security hardening - see `docs/security-audit.md`; built on Phase 8's dashboard) - earlier: **Phase 8 complete** (dashboard polish, built entirely on existing Phase 1-7 APIs with zero backend logic changes): a 30-site batch UI (previously missing from the frontend entirely) with live progress, per-site status, report downloads, and drill-down into any site's full single-scan view; a dedicated "works over IPv4 but fails over IPv6" highlight using the existing IPV6_BROKEN comparison label; dependency-graph host nodes now show explicit IPv4/IPv6 status chips; a Blocked filter and a legend were added to the resources table; and a frontend test suite (Vitest + Testing Library, 35 tests) was added alongside one real, non-mocked end-to-end verification driving the actual built UI against the actual backend).

## Run (no Docker needed)
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium            # on a Linux VPS: playwright install --with-deps chromium
uvicorn app.main:app --reload          # http://localhost:8000/docs
```
```bash
curl -X POST localhost:8000/api/scan -H 'content-type: application/json' -d '{"url":"https://example.com"}'
curl localhost:8000/api/scan/<scan_id>
curl localhost:8000/api/scan/<scan_id>/resources
```
Extra endpoints (Phase 2): `GET /api/context` (scanner egress/geo/resolver; **check `ipv6_egress_ok` is true on the VPS
before measuring**), `GET /api/scan/{id}/context`, `GET /api/scan/{id}/probes` now includes, per (host, port, family): `verdict` (e.g. `IPv6_REACHABLE`, `TCP_FAILURE`, `BLOCKED`, `NOT_TESTED`), `failure_stage`/`failure_subtype`, `family_comparison` (`BOTH_OK` / `IPV6_BROKEN` / `IPV4_BROKEN` / `BOTH_BROKEN` / `INCONCLUSIVE`), and timings.

Tests: `pytest -q` (the real-browser test skips itself if Chromium isn't installed).

## Run the frontend
```bash
cd frontend
npm install
npm run dev             # http://localhost:5173, expects the backend on :8000
npm run build            # production build -> frontend/dist
```
`VITE_API_BASE` overrides the backend URL if it's not on `localhost:8000`.

## Configuration (env vars)
`AUDITOR_MAX_RESOURCES`, `AUDITOR_PAGE_TIMEOUT_MS`, `AUDITOR_SCAN_DEADLINE_S`, `AUDITOR_MAX_CONCURRENT_SCANS`,
`AUDITOR_ALLOWED_PORTS`, `AUDITOR_SSRF_ALLOW_HOSTS` (controlled-site hostnames for local Docker dev only),
`AUDITOR_DNS_TIMEOUT_S`, `AUDITOR_PROBE_CONCURRENCY`, `AUDITOR_CONTEXT_TTL_S`, `AUDITOR_TCP_TIMEOUT_S`, `AUDITOR_TLS_TIMEOUT_S`, `AUDITOR_HTTP_TIMEOUT_S`, `AUDITOR_MAX_ADDRESSES_PER_FAMILY`, `AUDITOR_CHROMIUM_NO_SANDBOX=1` (containers running as root), `AUDITOR_DB_URL`.

## Controlled test site (Phase 5)
See `controlled-site/README.md`. Run its detection test suite with:
```bash
python3 -m pytest controlled-site/tests -q
```
This starts the seeded origin server as a real subprocess and feeds it through the actual
scanner classifier, asserting every seeded DNS/TCP/TLS/HTTP failure is detected correctly.
Final measurements use the site deployed publicly per `deploy/DEPLOY.md`, not this test.

## Batch scanning (Phase 6)
```bash
curl -X POST localhost:8000/api/batch-scan -H 'content-type: application/json' -d '{}'
curl localhost:8000/api/batch-scan/<batch_id>              # live progress + status summary
curl localhost:8000/api/batch-scan/<batch_id>/sites        # per-site name/url/scan_id/status
```
An empty body `{}` loads the default `backend/sites.json` plus the controlled test site (if
`AUDITOR_CONTROLLED_SITE_URL` is set); `{"sites": [...], "include_controlled": false}` overrides
both. New config: `AUDITOR_BATCH_CONCURRENCY` (default 3), `AUDITOR_BATCH_SITE_TIMEOUT_S` (default
150), `AUDITOR_BATCH_MAX_SITES` (default 50), `AUDITOR_SITES_CONFIG`, `AUDITOR_CONTROLLED_SITE_URL`.

## Reports (Phase 7)
```bash
curl localhost:8000/api/scan/<scan_id>/report/json
curl localhost:8000/api/scan/<scan_id>/report/csv
curl localhost:8000/api/batch-scan/<batch_id>/report/json
curl localhost:8000/api/batch-scan/<batch_id>/report/csv
```
Built purely from stored Phase 1-6 data (`app/reports/`); no scanning/probing code was
changed. `app/reports/redact.py` strips embedded URL credentials and redacts sensitive
query-parameter values (tokens, API keys, session ids, JWTs) before anything is exported -
the capture pipeline itself never stores headers or cookies, so URLs are the one real
place a secret could otherwise leak into a report.

## Frontend tests (Phase 8)
```bash
cd frontend
npm test           # Vitest + Testing Library, 35 tests, ~10s
```
Covers: loading a scan (COMPLETED/PARTIAL/BLOCKED/SCAN_FAILED), empty resources, Unknown
measurement context, IPv4/IPv6 verdict rendering (including NOT_TESTED never rendering as
a confirmed failure), batch progress over real polling intervals, and the batch-to-single
drill-down. No backend or scanning/probing/classification/batch/report code was changed;
all 178 pre-existing backend tests and 6 controlled-site tests still pass unmodified.

## Security (Phase 9)
Audit, per-finding classification (fixed / mitigated / limitation) and a VPS deployment
checklist: `docs/security-audit.md`. Regression tests: `backend/tests/test_security_hardening.py`.
New env vars: `AUDITOR_MAX_REDIRECTS` (15), `AUDITOR_MAX_REQUEST_BODY_BYTES` (1 MiB),
`AUDITOR_MAX_HOSTS_PER_SCAN` (100). **Read the limitations section before exposing the API:
there is no authentication, and an egress firewall is required to fully close DNS rebinding.**
