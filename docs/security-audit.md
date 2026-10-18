# Phase 9 security audit (PS-027 auditor, Phases 1-8)

Scope: SSRF / DNS rebinding, redirect security, IPv4/IPv6 address validation, URL
parsing, resource exhaustion, timeouts, concurrency, sensitive-data leakage, API input
validation, report security, frontend injection, deployment/container security.
Method: code review plus direct experiments (not assumptions) - every "fixed" row has a
regression test in `backend/tests/test_security_hardening.py`. Scanning, DNS, probing,
classification, batch and report *methodology* was not changed.

Classification: **FIXED** (code change + test) / **MITIGATED** (already safe, verified,
and why) / **LIMITATION** (not closed here; why, and what closes it).

## Headline finding

**F2 - redirect targets bypassed the SSRF guard (Phases 1-8). FIXED.** The guard used
Playwright's `route()`. Playwright deliberately never re-invokes route handlers for
requests produced by an HTTP redirect (microsoft/playwright#2617; still true in #34994).
Any server the scanner visited could answer `302 -> http://169.254.169.254/...` and
Chromium would connect there, no DNS-rebinding timing needed. Reproduced against real
Chromium (the route handler fired once per chain, never for the hops), then fixed by
intercepting through CDP's `Fetch` domain (`FetchInterceptor` in `scanner/browser.py`),
which does fire per hop. Fails closed on interceptor errors. The existing `Network`-domain
observation pipeline is untouched and was verified to coexist unchanged.

## Findings

| # | Area | Finding | Class | Why / evidence |
|---|------|---------|-------|----------------|
| F1 | IP validation | Legacy IPv4 literals (`2130706433`, `0x7f000001`, `017700000001`, `127.1`) are rejected by `ipaddress` but accepted by Chromium. Was safe on glibc only because `getaddrinfo` happens to parse them; dnspython (probe path) is safe only by NXDOMAIN. | FIXED | Explicit OS-independent `normalize_ip_literal()` (uses `inet_aton`); protection no longer depends on libc (musl differs). |
| F2 | Redirect / SSRF | See headline. | FIXED | 4 real-browser tests (metadata redirect, obscured-literal redirect, multi-hop, normal redirects unaffected). |
| F3 | Redirect / exhaustion | No app-owned redirect limit (only Chromium's internal ~20). | FIXED | `AUDITOR_MAX_REDIRECTS` (15), enforced in the same interceptor; real-browser tests at 25 hops (blocked) and 5 hops (completes). |
| F4a | DNS rebinding, browser path | Guard and Chromium resolve separately (TOCTOU). | FIXED (trust side) | Post-connection `remote_ip` re-check reclassifies any resource that actually connected to a non-public address as `BLOCKED`. |
| F4b | DNS rebinding, residual | One TCP SYN to a rebound address can still be sent before detection. | LIMITATION | Only an egress firewall / network policy below the app closes it. Required for any real deployment (see checklist). |
| F4c | DNS rebinding, probe path | Probes reuse the same resolved address list that was SSRF-checked. | MITIGATED | No second resolution, so no TOCTOU window; probes also never follow redirects. |
| F5 | Data leakage | Redaction existed only on `/report/*`; live endpoints the dashboard polls (`/scan`, `/resources`, `/graph`, `/probes`, `/batch-scan/*/sites`) returned raw URLs/errors. | FIXED | Same `redact_url`/`redact_text` applied at the Pydantic serialization layer. DB still holds raw data. |
| F6 | Data leakage | `redact_text` missed a URL pasted into free text. | FIXED | Embedded URLs now pass through `redact_url`. Caught by a failing test, not assumed. |
| F7 | Report security | CSV/formula injection (CWE-1236): cells starting `= + - @ \t \r`. | FIXED | OWASP leading-apostrophe mitigation on every field; round-trip as data preserves the text. |
| F8a | Exhaustion / input | Unbounded request body parsed before validation. | FIXED | `MaxBodySizeMiddleware` (1 MiB, `Content-Length`) returns 413 early. |
| F8b | Exhaustion / input | Chunked uploads without `Content-Length` bypass F8a. | LIMITATION | Pydantic `max_length` (below) bounds impact after parsing; a streaming reader was judged riskier than the gap. Put a reverse proxy body limit in front in production. |
| F9 | API validation | `sites` was a bare `list[dict]`. | FIXED | `SiteInput` (url required, <=2048; name <=255) and list <=500 -> framework 422. Note: missing `url` now returns 422 (was 400); `test_api.py` updated for that, the rejection itself is stricter, not weaker. |
| F10 | Exhaustion | `max_resources` bounds resources, not distinct hosts probed. | FIXED | `AUDITOR_MAX_HOSTS_PER_SCAN` (100, discovery order). Excess hosts show `HOST_LIMIT_EXCEEDED` -> `NOT_TESTED`, never connected to, never silently dropped. |
| F11 | Container | Controlled-site image ran as root. | FIXED (unverified at runtime) | Non-root user; `cap_drop: ALL` + `NET_BIND_SERVICE` only. **No Docker daemon was available here**: YAML validated, not executed. Smoke-test on first use. |
| F12 | Frontend injection | Searched for `dangerouslySetInnerHTML`, `eval`, `new Function`, `document.write`, `innerHTML`. | MITIGATED | None found. Every `href` is built from server-generated scan/batch IDs; discovered URLs are only rendered as inert text, never as links, `src`, or iframes. |
| F13 | SQL injection | Searched for raw SQL / formatted `execute`/`text()`. | MITIGATED | None; SQLAlchemy ORM only. |
| F14 | TLS | Cert validation. | MITIGATED | Browser `ignore_https_errors=False`; probes use `ssl.create_default_context()`; bad certs surface as `TLS_FAILURE`/`CERT_VERIFY`. |
| F15 | Request injection | CRLF/host injection in probe HTTP request. | MITIGATED | Phase 3 validation + tests (`test_request_building_is_injection_safe`). |
| F16 | Concurrency | Browser/probe/batch concurrency. | MITIGATED | Global browser semaphore is shared by single scans and all batches, plus per-batch and per-scan limits, per-stage timeouts, scan deadline, per-site batch timeout. |
| F17 | Transparency | Redirect misrepresentation in reports. | MITIGATED | Reports always carry both `target` and `final_url`. A blocked top-level redirect ends `PARTIAL` with `ERR_BLOCKED_BY_CLIENT`, never `COMPLETED` (tested). |
| F18 | Error leakage | Debug/tracebacks in responses. | MITIGATED | FastAPI debug off; errors stored/returned are application-authored strings, redacted on output. |

## Documented limitations (not fixed here)

1. **No authentication or authorization.** Anyone who can reach the API can start scans
   and read results. The brief never asked for auth; adding it is a feature. Deploy behind
   a reverse proxy / network ACL / VPN.
2. **Unbounded queued scans/batches.** Actual concurrency is bounded, but a client can
   still create unlimited `Scan`/`Batch` rows and queued tasks (storage growth, not CPU).
   A queue-depth cap needs design (where to count safely under concurrency, what to
   return); a half-implemented setting was removed rather than left implying protection.
3. **Browser isolation is reduced on purpose.** Phase 1 launches Chromium with site
   isolation disabled so one CDP session sees cross-site iframe traffic. A renderer
   exploit from a hostile page therefore has less to cross. Run the scanner in a VM or
   container, as a non-root user, with the egress firewall below. `--no-sandbox`
   (`AUDITOR_CHROMIUM_NO_SANDBOX=1`) removes the OS sandbox too - only inside a container
   you already trust to be disposable.
4. **Interception coverage not individually verified for:** WebSocket handshakes and
   cross-origin iframe subrequests under the Fetch domain. The existing integration tests
   pass and the post-connection `remote_ip` check (F4a) applies to every recorded request,
   but I did not write dedicated tests for those two cases.
5. **Application logs are not redacted.** The requirement and fix cover everything leaving
   via the API/reports. `log.exception` output is an operator-trusted surface.
6. **CORS allowlist is hardcoded to `http://localhost:5173`.** Fine for development;
   change it for any real frontend origin (and keep it an explicit list, never `*`).
7. **Unicode/IDN normalization edge cases** (e.g. fullwidth digits) are not exhaustively
   handled in host validation beyond what Chromium/`urlsplit` normalize.
8. **No backend Dockerfile.** Docker stayed optional per the brief; only the controlled
   site has one. Guidance below instead.

## Deployment checklist (for the dual-stack VPS)

- Egress firewall: block RFC1918, loopback, link-local (`169.254.0.0/16`, incl. cloud
  metadata), `fc00::/7`, `fe80::/10` from the scanner user. This is the layer that
  closes F4b.
- Run uvicorn and Chromium as a dedicated unprivileged user; never as root.
- Put TLS, auth, and a request-body limit in a reverse proxy in front of the API.
- Keep the API off public interfaces (bind `127.0.0.1` / private network).
- Set `AUDITOR_SSRF_ALLOW_HOSTS` only for the controlled-site hostnames, never broader.
- SQLite file `0600`, owned by the service user; back up outside the web root.
- New knobs: `AUDITOR_MAX_REDIRECTS`, `AUDITOR_MAX_REQUEST_BODY_BYTES`,
  `AUDITOR_MAX_HOSTS_PER_SCAN`.
