# Design decisions (confirmed)
1. Scans run on a dual-stack cloud VM/VPS; the laptop is for development and the dashboard only.
2. The controlled IPv4-only site is built in-repo, deployed publicly on the same VPS, with a Docker/local fallback for development. Final measurements use the public deployment.
3. Geolocation: scanner host's public IP via a free API; resolver info recorded; anything undeterminable is stored as `Unknown`, never inferred.
4. Readiness = resource-level ratio (primary), plus host-level ratio and a critical-path verdict. This is OUR measurement metric, not an official AIORI score.
5. Priority: mandatory PS-027 > reliability/reproducibility > UI polish > stretch. The IPv6-only browser pass is deferred until all mandatory items work.

# Phase 1 notes / known limits
- Chromium runs with site isolation disabled so a single CDP session captures cross-site iframe traffic.
- `remote_ip`/`remote_family` show what a dual-stack browser used (Happy Eyeballs); they are NOT an IPv6 verdict.
- CORS preflights and data:/blob: URLs are excluded from resources.
- Redirect count is bounded only by Chromium's built-in limit until Phase 9.
- SSRF guard resolves hosts separately from Chromium (DNS-rebinding window); use an egress firewall on the VPS.

# Phase 2 notes
- DNS is resolved by the scanner's OS resolver (dnspython). Chromium may use its own resolver, so answers can differ; the recorded resolver is the scanner's, not the browser's.
- DNS statuses: OK, NO_RECORD (NOERROR/NODATA), NXDOMAIN, TIMEOUT, RESOLUTION_ERROR (SERVFAIL etc.), LITERAL, NOT_APPLICABLE, BLOCKED. "No record" is deliberately different from "lookup failed".
- `resource.ipv4_addresses` / `ipv6_addresses` = addresses ADVERTISED in DNS, not proof of connectivity.
- Resolver context: configured nameservers from /etc/resolv.conf; if it is a local stub (e.g. 127.0.0.53) the upstreams are read from /run/systemd/resolve/resolv.conf; `resolver_egress_ip` comes from a whoami.akamai.net query (the recursive resolver's public address as seen from outside). Any of these can be Unknown, e.g. inside Docker.
- Egress preflight = TCP handshake to well-known literal IPs per family (no DNS involved). `ipv6_egress_ok=false` means IPv6 probe results must be NOT_TESTED, not target failures.
- Geolocation = approximate, from the scanner's public IP (prefers IPv4) via ipinfo.io, falling back to ipwho.is; source and IP are recorded. Context is cached for AUDITOR_CONTEXT_TTL_S (default 300s) so a 30-site batch doesn't hammer the APIs; each scan stores a copy with its own `collected_at`.
- The host_probe table already has tcp/tls/http columns (default NOT_TESTED) for Phase 3.

# Phase 3 notes
- Stage order is fixed: DNS -> TCP -> TLS -> HTTP. The first failing stage is recorded as
  `failure_stage`/`failure_subtype`; later stages are stored as `NOT_REACHED`, matching the
  brief's demo screen ("TLS: NOT REACHED").
- TCP and TLS run on the SAME already-connected socket (`asyncio.StreamWriter.start_tls`), so a TLS
  failure can never be confused with a fresh TCP failure to a different address.
- HTTP stage is deliberately minimal: one `GET` with `Range: bytes=0-0` and `Connection: close`,
  reading only the response head. Any syntactically valid HTTP/1.x status line is a stage PASS;
  `classifier.http_outcome()` then separately decides whether the *code* counts as a failure:
    - 5xx -> HTTP_FAILURE (server/edge broken on this path)
    - 401/403/429 -> BLOCKED (bot wall / rate limit / hotlink protection - not an IPv6 finding)
    - everything else (incl. 3xx, 404) -> reachable
  Confirmed live against example.com/Cloudflare: TLS completed (TLSv1.3), HTTP responded 403,
  and the probe correctly reported BLOCKED rather than a TLS or HTTP failure.
- Multiple advertised addresses per family are tried concurrently (`connect_any`), like a browser's
  Happy Eyeballs; the first to connect is used for TLS/HTTP, others are recorded as
  `addresses_tested`/`addresses_reachable` for a "partially reachable" signal.
- `egress_ok=False` for a family (from Phase 2's context) short-circuits that family to `NOT_TESTED`
  before any socket is opened - the scanner's own network limits must never look like target failures.
  A DNS-stage finding is still reported even with no egress for that family, since DNS needs no egress
  in the tested family (e.g. an A-only DNS resolver on an IPv6-only scanner can still see "NO_RECORD").
- `family_comparison` per host:port: BOTH_OK / IPV6_BROKEN / IPV4_BROKEN / BOTH_BROKEN / INCONCLUSIVE
  (INCONCLUSIVE when either side is NOT_TESTED/BLOCKED/SCAN_FAILED - refuses to guess).
- SSRF defence in depth: even though Phase 2's DNS stage already blocks non-public addresses, the
  probe layer re-checks the address before opening a socket and never calls the connect function for
  a blocked address (verified: the injected connect spy is never invoked).
- Known real asyncio quirk (found and fixed via direct verification, not assumption): a TLS handshake
  timeout raises `ConnectionAbortedError` with a specific message, not `TimeoutError`. Classified
  explicitly, verified end-to-end against a real plain-HTTP server.
- IPv6 loopback (`::1`) is unavailable in the current dev sandbox, so the IPv6-specific real-socket
  test is skipped there and will run for real on the dual-stack VPS. IPv4 real-socket paths (success,
  refused, reset, timeout, malformed response, self-signed cert, wrong hostname, 5xx, 403) are all
  exercised against real local servers.

# Phase 4 notes
- `dependency_graph.py` builds one graph node per HOST (colored by that host's IPv6 verdict:
  green/yellow/red/gray, matching the brief's legend) plus one node per RESOURCE (colored gray unless
  it actually LOADED, so a failed browser fetch never inherits its host's color and implies success).
  Edges: resource -> parent resource (from Phase 1's initiator tracking, `kind: "initiator"`,
  dashed if `inferred`), and resource -> its host group (`kind: "hosts"`).
- Host color logic distinguishes "every tested port reachable" (green) from "some reachable, some not
  or some untested" (yellow) from "nothing tested" (gray) from "something failed" (red) - it never
  colors a host green or red based on an untested port.
- Frontend: Vite + React + Tailwind + React Flow, built as a real project (not a published artifact),
  per the brief's explicit architecture. Design follows brief section 21 exactly (light background,
  dark-blue primary, compact tables, status badges, minimal motion) rather than a generic AI-dashboard
  look: IBM Plex Sans/Mono, thin 1px borders, 4px max radius, no shadows/gradients, underlined text
  tabs. A simple two-tier layout places host nodes above their resources; smoothstep edge routing
  keeps the tree readable without a layout library (unnecessary for a hackathon-sized graph).
- Verified against REAL running servers (not just unit tests): started the FastAPI backend, the Vite
  dev server, and a local test HTTP site, drove the actual dashboard with headless Chromium via
  Playwright, and confirmed: URL entry -> polling -> completed status -> every tab renders -> clicking
  a graph node shows the correct DNS/TCP/TLS/HTTP breakdown -> zero console/page errors (aside from a
  sandbox-only font-CDN block that will not occur in a normal deployment).
- Found and fixed a real correctness bug during this verification, not merely a cosmetic one: the
  Resources table's IPv4/IPv6 columns showed "✗" (failed) for a verdict of NOT_TESTED, which would
  have misrepresented "we didn't test this" as "this is broken" - the exact mistake the whole project
  exists to avoid. Fixed so only a confirmed failure verdict renders "✗"; NOT_TESTED/NOT_APPLICABLE/
  BLOCKED render "—". The "IPv4-only" filter had the same flaw and was fixed the same way.
- Confirmed live against https://example.com through the full UI end-to-end: DNS OK, TCP PASS, TLS
  PASS (TLSv1.3), HTTP 403 from Cloudflare correctly classified and displayed as BLOCKED with the
  explanatory text, not as a TLS/HTTP failure or a fabricated IPv6 problem.
- Known gap carried forward: this dev sandbox has no IPv6 egress (confirmed since Phase 2), so no
  screenshot here shows a real green/red IPv6 verdict end-to-end - only NOT_TESTED. This will look
  different, and more interesting, on the dual-stack VPS.

# Phase 5 notes
- `seed_server.py` is the core trick: one small server whose IPv4 and IPv6 listening
  addresses can behave DIFFERENTLY (pass / tcp_fail / tls_fail / http_fail), which lets a
  single hostname seed a SPECIFIC failure stage on its IPv6 path without touching DNS.
  tls_fail accepts the TCP connection then closes before any TLS bytes are sent (a real
  handshake failure, not a timeout); http_fail completes real TLS then returns 500 for
  every request, so TCP and TLS genuinely pass before the seeded failure.
- Verified for real, not just authored: ran all four modes as live processes (using a
  second loopback ALIAS, 127.0.0.2, as a stand-in for "the IPv6 path" since this sandbox
  has no real IPv6 - consistent with every earlier phase's finding), then fed each one
  through the ACTUAL Phase 3 `probe_family()` classifier and confirmed every verdict
  matches `seeded.json` exactly: pass->IPv4_REACHABLE, tcp_fail->TCP_FAILURE/REFUSED,
  tls_fail->TLS_FAILURE/RESET (with tcp_status=PASS, confirming TCP genuinely succeeded
  first), http_fail->HTTP_FAILURE/SERVER_ERROR (with tcp_status=PASS and tls_status=PASS).
  This is now a permanent automated test (`controlled-site/tests/test_seeded_detection.py`,
  6 tests, run as real subprocesses), not just a one-off script.
- Two real bugs were caught and fixed during this verification, not just cosmetic ones:
  (1) the SSRF guard correctly rejected the loopback test addresses at first, requiring
  the same `ssrf_allow_hosts` test pattern used in earlier phases - a reminder that the
  guard's default posture is deny, even for test infrastructure. (2) the first draft of
  `docker-compose.yml`/`dnsmasq.conf` used an INVALID IPv6 address (`fd00:ps027::10` -
  "ps027" is not legal hex), which would have silently broken the entire IPv6 side of the
  local Docker fallback. Caught by directly validating every address with Python's
  `ipaddress` module before trusting the config, and replaced with a valid ULA prefix
  (`fd00:d0c5::/64`).
- Docker/dnsmasq themselves could NOT be executed in this sandbox (neither is installed),
  so the compose file and dnsmasq config are validated as far as possible without a daemon:
  YAML parses correctly, every IPv6 address is a real valid address, the Dockerfile's
  COPY sources all exist, and the port-parsing logic (`rsplit(":", 1)` on strings like
  `fd00:d0c5::10:80`) was verified directly against Python's own address parser. The
  actual container networking (whether the Docker IPv6 bridge behaves as documented) is
  unverified here and should be smoke-tested on first real use, per `docker/README.md`.
- The VPS deployment strategy (`deploy/DEPLOY.md`) gives each seeded "broken" hostname its
  OWN dedicated public IPv6 address, because virtual-hosting by hostname can't change
  transport-layer (TCP/TLS) behavior - the Host header isn't visible until after TCP and
  TLS already succeeded or failed. This is stated explicitly in the deploy doc so it isn't
  mistaken for an oversight.
- `v4only-img` needs no special server logic at all - it's a pure DNS fact (no AAAA
  record), and `seed_server.py` with no `--v6-bind` naturally satisfies it.

# Phase 6 notes
- The batch runner reuses `scan_runner.run_scan` completely UNCHANGED for every site - a
  batch is not a second code path that could silently diverge from, or weaken, a single
  scan's SSRF validation or DNS/TCP/TLS/HTTP classification. Verified directly, not just
  argued: `test_blocked_target_among_others_does_not_stop_the_batch` sends a real literal
  link-local IP (`169.254.169.254`) through the REAL `run_scan`/SSRF guard inside a batch
  and confirms it comes back `BLOCKED` with the batch still completing - the exact same
  guard, the exact same outcome, as a single scan.
- No shared, concurrently-mutated summary state. `Batch.status` is written only by the one
  orchestrating coroutine; every site's live status is read by joining `BatchSite -> Scan`
  at query time (`batch_progress()`), never cached - so concurrent site completions cannot
  race on a shared read-modify-write field. This was a deliberate design choice made
  BEFORE writing code, specifically to avoid the kind of race bug this project already hit
  once (Phase 5's dnsmasq/compose mistakes) and generally to avoid the classic "two
  background tasks read-modify-write the same JSON blob" bug.
- Each site gets its OWN `Scan` row (and thus its own `scan_id`) created up front, before
  any scanning starts - duplicate URLs in the input never collide or get silently merged.
  Verified directly: `test_duplicate_urls_produce_independent_scans_not_merged` feeds the
  same URL in twice under different names and confirms two distinct scan_ids, both kept.
- A real Python pitfall was caught and fixed during testing, not assumed correct: both
  `run_batch(..., scan_fn=_run_one_site)` and `_run_one_site(..., run_fn=run_scan)` used
  mutable function references as DEFAULT ARGUMENT VALUES, which Python binds once at
  function-definition time - so `monkeypatch.setattr(batch_runner, "_run_one_site", fake)`
  silently had NO effect on code already using the old default, and a test meant to run in
  milliseconds instead spent 57 real seconds making real (failing) network calls before
  the bug was caught by watching the test actually take 57 seconds and asking why. Fixed
  by defaulting both to `None` and resolving the real function by name inside the function
  body at call time, which Python does look up dynamically. This is exactly the kind of
  bug that LOOKS like correct, idiomatic dependency injection but silently isn't - worth
  flagging prominently rather than quietly fixing, since the test suite would have kept
  "passing" against real network calls instead of fast fakes without anyone noticing.
- Per-site timeout (`_run_one_site`, default 150s) is layered ON TOP of each scan's own
  internal page-load deadline (Phase 1's `scan_deadline_s`, default 90s) - two independent
  bounds, so a site that somehow hangs past its own internal timeout (a bug in a future
  phase, a stuck DNS/probe stage with no bound of its own, etc.) still can't stall the
  whole batch indefinitely. `_force_terminal()` only overwrites a NON-terminal scan, so a
  timeout firing at the exact moment a real result lands can't clobber it - covered by
  `test_timeout_does_not_clobber_a_result_that_finished_just_in_time`.
- Concurrency is a batch-local `asyncio.Semaphore(settings.batch_concurrency)`, separate
  from the single-scan module's own global semaphore (Phase 1's `max_concurrent_scans`,
  still used unchanged by `run_scan` itself for its browser launch). This means a batch
  run is bounded by BOTH limits simultaneously (the stricter one wins) rather than one
  hidden global limit silently governing both single-scan and batch-scan concurrency -
  easier to reason about and to test in isolation (`test_batch_respects_concurrency_limit`,
  `test_batch_concurrency_of_one_is_fully_serial`), without touching Phase 1's existing
  semaphore or its tests at all.
- `sites.json` is a genuine configuration file, never hard-coded into scanner logic (PS-027
  requirement): 30 real, diverse domains (search, wiki, CDN/infra, news, e-commerce,
  dev/package registries, standards bodies, Indian government/education/news/e-commerce).
  The controlled test site is intentionally a SEPARATE concern from the 30 - appended only
  if `AUDITOR_CONTROLLED_SITE_URL` is configured and `include_controlled` is true - matching
  the brief's exact phrasing "30 selected websites PLUS 1 controlled test site" rather than
  folding it into the 30 as just another list entry.
- `GET /api/batch-scan/{id}/sites` is the hand-off point for later phases: each row's
  `scan_id` is a fully ordinary scan_id, usable as-is with every existing Phase 1-4
  endpoint (`/resources`, `/probes`, `/graph`, and Phase 7's upcoming `/report/json|csv`).
  Verified directly in `test_batch_scan_lifecycle_via_api`, which after a batch completes
  calls `GET /api/scan/{scan_id}` for every site and confirms it resolves normally - this
  is the concrete proof that batch data is ready to feed the aggregate report and the
  dependency-graph UI without any new endpoint shape being invented for it.
- Real, non-faked verification: `test_real_batch_of_two_local_sites_end_to_end` runs an
  actual 2-site batch through the REAL `run_scan` (real Chromium, real DNS, real
  TCP/TLS/HTTP probes) against real local HTTP servers, confirming the full stack - not
  just the orchestration logic in isolation - works together. All 134 pre-existing backend
  tests still pass completely unmodified, plus 18 new Phase 6 tests (152 passed, 1 skipped
  total), and all 6 controlled-site tests still pass unchanged - confirming Phase 1-5
  behavior, SSRF protection, and failure classification are fully preserved.

# Phase 7 notes
- Reports are built entirely by NEW, read-only code (`app/reports/`) querying already-
  stored Phase 1-6 tables (`Scan`, `Resource`, `HostProbe`, `MeasurementContext`, `Batch`,
  `BatchSite`). No scanning/probing/classification file was modified, and no new column
  or write path was added to any existing table. All 152 pre-existing backend tests and
  all 6 controlled-site tests still pass completely unmodified.
- Verdict terminology is read and re-emitted VERBATIM from `HostProbe` (`IPv6_REACHABLE`,
  `TCP_FAILURE`, `TLS_FAILURE`, `HTTP_FAILURE`, `BLOCKED`, `NOT_TESTED`, `NOT_REACHED`,
  failure_stage/failure_subtype) - the report layer never renames, reformats, or
  reinterprets a verdict. Tested explicitly (`test_..._verdict_terminology_preserved`).
- IPv4 and IPv6 are reported as two clearly separate, equally-structured blocks per
  resource (`resource.ipv4`, `resource.ipv6` in JSON; `ipv4_*`/`ipv6_*` columns in CSV),
  never merged into one ambiguous column - this intentionally departs from the ORIGINAL
  brief's section-16 CSV sketch (which listed single `dns_status`/`tcp_status`/etc.
  columns), because that sketch predates this project's actual dual-stack-per-family data
  model and the user's explicit Phase 7 instruction to "distinguish IPv4 from IPv6
  results." Adapting the column layout to fit the real, richer model - while keeping
  every original column's intent - was judged truer to the spirit of the brief than
  copying column names that don't fit what the scanner actually measures.
- Scope deliberately excludes a computed "IPv6 readiness %" score. The user's Phase 7
  instructions list exactly what a report must contain (verdict terms, IPv4/IPv6
  distinction, context, per-site summary, batch support) and do not mention a score;
  inventing a new formula not asked for in this phase would be scope creep beyond what
  was requested. Reports carry the existing, ALREADY-COMPUTED counts verbatim (Phase 3's
  `probe_summary()`/Phase 1's `summarize()` output, stored on `Scan.summary`) with no new
  derived metric invented. The readiness-percentage gap noted since Phase 4 remains open
  and undecided, not silently resolved here.
- A batch report's per-site section is a SUMMARY (status, error, that site's own
  `scan.summary` counts) rather than a full resource dump for every site, to keep a
  30-site report a sane size; full per-resource detail for any one site is one call away
  via its own ordinary `scan_id` through the existing single-scan report endpoints - this
  is the literal "data that can later feed the... UI" hand-off Phase 6 was built for.
- Sensitive-data handling, concretely scoped to what's actually true of this codebase
  (checked directly, not assumed): the capture pipeline has never read or stored HTTP
  request/response headers, cookies, or Authorization values anywhere (confirmed by
  grepping scanner/browser.py and scanner/resource_discovery.py before writing a single
  line of redaction code). The one REAL exposure path is a URL's own embedded Basic-Auth
  userinfo or query-string parameters (a third-party script's tracking pixel, say,
  attaching `?api_key=...`) - genuinely discovered and stored verbatim by Phase 1. A new
  `reports/redact.py` strips embedded credentials and redacts sensitive query-parameter
  values (an exact-match name list, plus a JWT-shape check regardless of parameter name)
  from every URL-bearing report field, plus a defensive free-text scrub for
  error/detail fields (not currently exercised by real data, but cheap insurance). This
  is applied ONLY at report-generation time; nothing stored in the database changes.
- TWO real bugs were caught by testing, not assumed correct on the first attempt:
  (1) The `Authorization:`/`Cookie:` free-text regex originally stopped at the first
  whitespace, so "Authorization: Bearer abc.def.ghi" was only partially redacted - the
  word "Bearer" was masked but the actual token sat in plain text right next to the
  redaction marker, which is worse than no redaction because it LOOKS safe. Caught by a
  test asserting the real secret value is absent from the output (not just that `[REDACTED]`
  is present), fixed by widening the pattern to consume to the next newline/semicolon.
  (2) `redact_url()` originally rebuilt every URL's query string via `urlencode()`
  unconditionally, which silently re-percent-encodes characters (commas, quotes) that
  were not originally escaped - corrupting URLs that had nothing sensitive in them at
  all. Caught by the CSV round-trip escaping test expecting the EXACT original URL back,
  not an approximately-similar one. Fixed so the function returns the input completely
  unchanged whenever nothing actually needs redacting, and only rebuilds the URL when a
  real redaction is happening.
- CSV correctness uses Python's `csv` module throughout (`csv.DictWriter`/`DictReader`),
  never manual string concatenation, and is proven (not just assumed) via a round-trip
  test: a field containing a literal comma, embedded quotes, AND an embedded newline all
  at once must come back byte-for-byte identical after being written and re-parsed.
- Duplicate resources (the same URL discovered twice, e.g. a failed request followed by a
  retry) are deliberately NOT deduplicated in a report - each discovered request is its
  own row, since merging them could hide a real finding (first attempt failed, retry
  succeeded). Duplicate HOSTS (several resources sharing one hostname) are tested to
  confirm the hostname->probe lookup used when assembling resource rows never
  cross-contaminates one host's verdict onto a different host's resources.
- Both single-scan and batch CSV reports reuse the exact same per-resource row-building
  function (`_resource_to_row`), so the two can never develop divergent column semantics;
  the batch CSV only adds leading `batch_id`/`site_index`/`site_name`/`site_url`/
  `site_status` columns. A site with zero resources (BLOCKED, SCAN_FAILED, or genuinely
  empty) still gets exactly one CSV row with its site columns filled in and resource
  columns blank, rather than vanishing from the export entirely - a missing row would
  misleadingly look like that site was never attempted.
- 27 new backend tests added (21 in `test_reports.py`, 6 in `test_api.py`), covering
  every case named in the Phase 7 instructions: basic correctness, empty/partial/failed
  scans, blocked targets, missing AND partial measurement context (`Unknown` only where
  genuinely unknown - a real `False` is preserved as `False`, never upgraded to
  "Unknown"), duplicate resources, duplicate hosts, CSV escaping, and batch reports
  (per-site summary, CSV one-row-per-site-resource, a resource-less site still
  represented, and batch-level redaction). All 179 backend tests collected, 178 passed,
  1 skipped (the pre-existing, unrelated IPv6-loopback sandbox limitation).

# Phase 8 notes
- Zero backend changes. No file under `backend/app/scanner/`, `backend/app/services/`,
  or `backend/app/reports/` was touched this phase - confirmed by all 178 pre-existing
  backend tests and all 6 controlled-site tests passing completely unmodified, both
  before and after this phase's work. Every new UI feature reads data the API already
  returned; nothing required a new backend field or endpoint.
- The 30-site batch UI was ENTIRELY MISSING from the frontend before this phase, despite
  the batch API existing since Phase 6 and batch reports since Phase 7 - a real gap this
  phase closes: `api/client.js` gained the batch endpoints, `hooks/useBatchPolling.js`
  mirrors the existing single-scan polling hook's shape, and `components/BatchView.jsx`
  renders live progress, a by-status breakdown, the full per-site table, and report
  download links that only appear once the batch is actually COMPLETED.
- `useScanPolling` was refactored (not rewritten from scratch) to extract a shared
  `pollUntilDone()` used by BOTH a brand-new scan (`start`) and attaching to an
  already-existing one (`loadExisting`) - this is what lets a batch's "View" button drop
  a site straight into the exact same single-scan dashboard (tabs, graph, highlight,
  everything) with no duplicated rendering logic and no second code path to drift from
  the first.
- The core deliverable - "which resources work over IPv4 but fail over IPv6, and exactly
  where does the IPv6 path fail" - is answered THREE ways, all from data the backend
  already computed, none of it new computation:
    1. `Ipv6BrokenHighlight` leads the Overview tab: lists every host:port whose
       Phase 3 `family_comparison` is literally `IPV6_BROKEN`, with a plain-English
       sentence built ONLY from the existing `failure_stage`/`failure_subtype`
       vocabulary (no new wording invented that could drift from what the classifier
       decided).
    2. The dependency graph's host nodes now show two small chips, `4` and `6`, colored
       from each family's own verdict (`scanner/dependency_graph.py` already returned
       `ipv4_verdict`/`ipv6_verdict` per host node since Phase 4 - this data was simply
       never rendered until now). A green `4` next to a red `6` is instantly scannable
       without clicking into the detail panel.
    3. The metric strip's lead number is now the real, already-computed
       `summary.probes.ipv4_vs_ipv6.IPV6_BROKEN` count, replacing a "readiness %" metric
       that had shown a permanent, non-functional "—" since Phase 4 (that field was
       never implemented, by design - see Phase 7 notes). This is a removal of dead,
       misleading UI and a replacement with a real number, not an invented score -
       consistent with this phase's explicit instruction not to invent one.
- `NOT_TESTED`/`NOT_REACHED`/`BLOCKED` handling, carried over correctly from Phase 4's
  original bug-fix and now extended: the resources table's ✓/✗/— convention is
  unchanged (— for anything not a CONFIRMED result), a "Blocked" filter chip was added
  (checking both `resource.load_status` and either family's verdict), and a visible
  legend caption was added under the table so the ✓/✗/— convention doesn't rely on
  institutional memory of a bug fixed four phases ago.
- Two real UI bugs were caught by writing tests, not assumed correct:
    1. `StatusBadge` was built in Phase 4 covering only probe/resource VERDICT terms
       (`IPv6_REACHABLE`, `TCP_FAILURE`, etc.). Phase 8 reuses the same component for
       scan/batch STATUS terms (`QUEUED`, `RUNNING`, `COMPLETED`, `PARTIAL`,
       `SCAN_FAILED`) for the first time, and NONE of those were in the style map -
       `SCAN_FAILED` (a genuine failure) was silently rendered with the exact same muted
       gray as `NOT_TESTED` (an absence of a finding), understating a real failure's
       severity. Caught by `BatchView.test.jsx` asserting the rendered CSS class, not
       just that some badge rendered. Fixed by adding all five status terms with
       semantically correct colors (green=success, amber=caveat/blocked,
       red=genuine failure, gray=nothing determined yet).
    2. (Test-fixture mistakes, not product bugs, but worth recording since they shaped
       the final tests): an early `MeasurementsView` test fixture left `geo_source`
       unset, which is impossible in the real API contract (Phase 2's
       `ScanContext.display()` always converts every field to a real value or the
       literal string `"Unknown"`, never leaves one as JS `undefined`) - the test
       fixture was corrected to match that real contract rather than the component
       being changed to accommodate an input shape the live API can never actually send.
- Testing strategy, deliberately split in two (mirroring how the BACKEND suite itself is
  structured throughout this whole project): FAST, deterministic component tests
  (Vitest + Testing Library, mocking `api/client.js` entirely) for every edge case named
  in the brief - loading a scan, partial/failed/blocked statuses, empty resources,
  Unknown context, IPv4/IPv6 verdict rendering, and batch progress including a REAL
  interval tick (not faked timers) proving the actual 1.5s polling logic updates the UI
  - plus ONE real, non-mocked, full-stack verification: an actual production build
  (`vite build`), served by `vite preview`, driven by real headless Chromium via
  Playwright, against the REAL FastAPI backend and REAL local HTTP test sites - covering
  the single-scan flow (including a live check against a real external dual-stack
  domain, reproducing the exact Cloudflare-403-correctly-classified-as-BLOCKED finding
  from Phase 3/4), the dependency graph's new dual chips, and a complete real batch run
  (start -> live progress -> completion -> report links appearing -> drilling into a
  site) - using Phase 6's own `sites.json` configurability to temporarily point the
  batch at two fast local test sites instead of the live internet, then restoring the
  original file afterward. 35 new frontend tests added (`npm test`), all passing;
  `npm run build` still succeeds; all 178 backend tests, 1 skip, and 6 controlled-site
  tests remain exactly as they were before this phase.
- One benign, self-correcting UI quirk observed during live verification, noted rather
  than silently ignored: on the very first poll tick after starting a batch, the
  per-site list (refreshed via its own `loadSites()` call) can show individual sites as
  `RUNNING` for a few hundred milliseconds before the top-level `batch.status` field's
  own poll catches up from `QUEUED` to `RUNNING` - both values are independently true
  reads of real backend state at slightly different instants, not a logic error, and it
  resolves itself within one 1.5s polling interval.

# Phase 9 notes
Full audit table, classifications and deployment checklist: `docs/security-audit.md`.
- Highest-severity result: redirect targets bypassed the Playwright `route()`-based SSRF
  guard since Phase 1 (Playwright intentionally never routes redirect hops). Fixed with
  CDP `Fetch` interception; the `Network`-domain measurement pipeline is unchanged.
- Two of my own assumptions were wrong and were corrected by experiment: I first expected
  legacy IPv4 literals to be an exploitable bypass (they were safe, but only by glibc
  accident - fixed to be explicit), and I first expected `route()` to see every redirect
  hop (it does not).
- Tests that failed were examined, not bent: one expected `400` where stricter Pydantic
  validation now returns `422` (rejection kept, status code updated with a comment); a
  failing `redact_text` test exposed a real gap (fixed in code); several of my own test
  designs were flawed (allowlisting `127.0.0.1` also allowlisted the "attack" target) and
  were redesigned rather than the guard loosened.
- Removed an unused `max_pending_scans` setting rather than ship a control that did not
  exist.
- Not run here: Docker (no daemon). Container changes are validated structurally only.
