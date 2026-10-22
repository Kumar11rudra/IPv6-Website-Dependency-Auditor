# IPv6 Website & Dependency Readiness Auditor

<div align="center">

![IPv6 Readiness Auditor](https://img.shields.io/badge/Dual--Stack-RFC%206555%20%2F%208305-blue?style=for-the-badge&logo=internet-explorer)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![TailwindCSS](https://img.shields.io/badge/Styling-TailwindCSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Tests](https://img.shields.io/badge/Tests-224%20Backend%20%7C%2039%20Frontend%20Passing-brightgreen?style=for-the-badge&logo=checkmarx)](https://github.com/Kumar11rudra/IPv6-Website-Dependency-Auditor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-2ea44f?style=for-the-badge&logo=githubpages&logoColor=white)](https://kumar11rudra.github.io/IPv6-Website-Dependency-Auditor/)

<br/>

**A modern, production-grade dual-stack audit engine that tests websites and all of their third-party dependencies over IPv4 and IPv6 independently using headless browser interception and multi-stage network diagnostics (DNS &rarr; TCP &rarr; TLS &rarr; HTTP).**

*An AAAA record alone is never treated as proof of IPv6 readiness.*

[🚀 Live Web App](https://kumar11rudra.github.io/IPv6-Website-Dependency-Auditor/) &bull;
[Key Features](#key-features) &bull;
[Architecture](#architecture) &bull;
[Quick Start](#quick-start) &bull;
[API Reference](#api-reference) &bull;
[Configuration](#configuration) &bull;
[Test Suites](#test-suites) &bull;
[Security](#security-hardening)

</div>

---

## Overview

Modern web applications pull hundreds of external resources—CDNs, tracking pixels, font providers, payment gateways, and authentication APIs. While the primary domain may resolve an IPv6 address (`AAAA` record), the website often **degrades or completely breaks** in IPv6-only or Happy Eyeballs fallback scenarios if critical third-party dependencies fail to resolve or respond over IPv6.

**IPv6 Website & Dependency Readiness Auditor** addresses this challenge by:
1. Loading target websites inside a real Chromium browser via Playwright and the Chrome DevTools Protocol (CDP).
2. Capturing all dynamic network requests, dependencies, and initiator chains.
3. Performing isolated, deterministic dual-stack probes (`DNS`, `TCP`, `TLS`, and `HTTP`) against every single discovered host.
4. Categorizing readiness into definitive verdicts (`BOTH_OK`, `IPV6_BROKEN`, `IPV4_BROKEN`, `BOTH_BROKEN`, `INCONCLUSIVE`).
5. Providing an interactive force-directed dependency graph, 30-site batch scanning, and sanitized JSON/CSV audit reports.

---

## Key Features

- **Real Browser Execution:** Employs headless Chromium to discover dynamic AJAX/Fetch calls, stylesheets, scripts, fonts, and iframes that raw HTTP crawlers miss.
- **Isolated Multi-Stage Probing:** Probes each discovered hostname independently across both IPv4 (`A`) and IPv6 (`AAAA`) through 4 discrete network stages:
  - **DNS:** Query resolution and A/AAAA validation
  - **TCP:** SYN/ACK handshake and round-trip latency
  - **TLS:** Certificate verification and SNI handshake
  - **HTTP:** HEAD/GET response codes and protocol negotiation
- **Identifies "IPv6 Broken" Dependencies:** Explicitly flags resources that succeed on IPv4 but fail on IPv6 (`IPV6_BROKEN`), uncovering silent dual-stack regressions.
- **Smart Dual-Stack Fallback Engine:** Accurate diagnostics on both native dual-stack VPS and environments without native IPv6 routing via authoritative DNS and global prefix verification.
- **Readiness Grade System:** Evaluates compliance and assigns definitive grades (`GRADE A+`, `A`, `B`, `C`, `F`) based on actual resource reachability.
- **Interactive 2D Topology Graph:** Visualizes dependency trees with clean multi-column host clusters, color-coded node verdicts, and detailed host inspection drawers.
- **1-Click Quick Scan Chips:** Instant testing for standard test domains (`uims.cuchd.in`, `google.com`, `wikipedia.org`, `github.com`, `cloudflare.com`).
- **Asset Category Filtering:** Fast sorting by Scripts, Stylesheets, Images, and Fonts in the resources table.
- **Dynamic Backend Switcher (`API: ⚙️`):** Configure and connect the dashboard to local servers, custom VPS endpoints, or Docker reverse proxies seamlessly.
- **High-Throughput 30-Site Batch Scanner:** Parallel asynchronous scanning for top domain sets with live progress bars, state persistence, and CSV/JSON summaries.
- **Privacy & SSRF Hardened:** Strips sensitive credentials/JWTs from URLs before export and enforces strict RFC 1918 / loopback SSRF guards.
- **Centered, Accessible UI:** Modern typography, dark/light harmonious color tokens, centered navigation tabs, and responsive layout.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │       User / Web Browser (Client)       │
                    └────────────────────┬────────────────────┘
                                         │
                         HTTP / REST API │  (Port 5173 / 8000)
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │      FastAPI High-Performance Core      │
                    │   • SSRF Protection Guard               │
                    │   • Batch Job Orchestrator              │
                    │   • Redaction & Report Serializer       │
                    └─────┬─────────────────────────────┬─────┘
                          │                             │
          1. Dynamic Page │             2. Multi-Stage  │
             Interception │                Dual-Stack   │
                          ▼                             ▼
        ┌───────────────────────────┐     ┌───────────────────────────┐
        │ Playwright / Chromium CDP │     │  Family Probe Diagnostics │
        │ • DOM Execution           │     │  • DNS Resolver (A / AAAA)│
        │ • Resource Tree Capture   │     │  • TCP Handshake (v4/v6)  │
        │ • Initiator Lineage       │     │  • TLS Handshake (SNI)    │
        └─────────────┬─────────────┘     │  • HTTP/1.1 & HTTP/2 Probe│
                      │                   └─────────────┬─────────────┘
                      └─────────────────┬───────────────┘
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │       Classifier & Verdict Engine       │
                    │  BOTH_OK | IPV6_BROKEN | IPV4_BROKEN     │
                    └───────────────────┬─────────────────────┘
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │         React 18 Dashboard UI           │
                    │  • D3.js Force-Directed Graph           │
                    │  • Dual-Stack Comparison Matrix         │
                    │  • Batch Live Progress & CSV/JSON Export│
                    └─────────────────────────────────────────┘
```

---

## Quick Start

### 1. One-Command Unified Launcher (Recommended)

The repository includes a unified runner that manages dependencies, port bindings, and launches both services concurrently:

```bash
# Clone the repository
git clone https://github.com/Kumar11rudra/IPv6-Website-Dependency-Auditor.git
cd IPv6-Website-Dependency-Auditor

# Launch both Backend (port 8000) and Frontend (port 5173)
python3 start.py
```

Once started:
- **Frontend Dashboard:** [http://localhost:5173](http://localhost:5173)
- **Backend API & Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- *(Opening `http://localhost:8000` automatically redirects to the Frontend Dashboard).*

---

### 2. Docker Compose (1-Command Containerized Run)

```bash
docker compose up -d --build
```
- **Web App:** [http://localhost](http://localhost) (Nginx reverse-proxies frontend and backend API)
- **Backend API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

### 3. Manual Setup (Alternative)

<details>
<summary>Click to view manual step-by-step setup</summary>

#### Backend
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium     # On Linux VPS: playwright install --with-deps chromium
uvicorn app.main:app --reload --port 8000
```

#### Frontend
```bash
cd frontend
npm install
npm run dev                     # Starts Vite on http://localhost:5173
```

</details>

---

## API Reference

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/scan` | Initiate a single-site scan with real browser interception |
| `GET` | `/api/scan/{id}` | Check scan status (`PENDING`, `RUNNING`, `COMPLETED`, etc.) |
| `GET` | `/api/scan/{id}/resources` | Retrieve discovered third-party resources and load statuses |
| `GET` | `/api/scan/{id}/probes` | Get discrete IPv4 vs. IPv6 network probe verdicts |
| `GET` | `/api/scan/{id}/graph` | Fetch graph nodes, edges, and legend for D3 visualization |
| `GET` | `/api/scan/{id}/report/json` | Download sanitized JSON compliance report |
| `GET` | `/api/scan/{id}/report/csv` | Download sanitized CSV compliance report |
| `POST` | `/api/batch-scan` | Trigger a 30-site concurrent batch audit |
| `GET` | `/api/batch-scan/{id}` | Poll batch progress and aggregate stats |
| `GET` | `/api/batch-scan/{id}/sites` | Retrieve site-by-site status in batch |
| `GET` | `/api/context` | Check scanner environment (egress IP, IPv6 capability, resolver) |
| `GET` | `/api/health` | Healthcheck and active scanner version |

### Example cURL Commands

```bash
# 1. Trigger a scan
curl -X POST http://localhost:8000/api/scan \
     -H 'Content-Type: application/json' \
     -d '{"url": "https://example.com"}'

# 2. Check scanner context (ensure IPv6 egress is active)
curl http://localhost:8000/api/context

# 3. Export sanitized JSON report
curl http://localhost:8000/api/scan/<SCAN_ID>/report/json -o audit-report.json
```

---

## Configuration

Customizable via environment variables or a `.env` file:

| Variable | Default | Purpose |
|:---------|:--------|:--------|
| `AUDITOR_DB_URL` | `sqlite:///./data/auditor.db` | Database connection string (SQLite or PostgreSQL) |
| `AUDITOR_MAX_RESOURCES` | `250` | Maximum resources intercepted per page scan |
| `AUDITOR_PAGE_TIMEOUT_MS` | `30000` | Browser navigation timeout (milliseconds) |
| `AUDITOR_SCAN_DEADLINE_S` | `90` | Overall scan deadline in seconds |
| `AUDITOR_MAX_CONCURRENT_SCANS` | `4` | Maximum parallel single scans |
| `AUDITOR_ALLOWED_PORTS` | `80,443,8080,8443` | Permitted outbound network ports |
| `AUDITOR_DNS_TIMEOUT_S` | `5.0` | DNS query timeout per family |
| `AUDITOR_TCP_TIMEOUT_S` | `5.0` | TCP connection timeout per family |
| `AUDITOR_TLS_TIMEOUT_S` | `5.0` | TLS handshake timeout per family |
| `AUDITOR_HTTP_TIMEOUT_S` | `8.0` | HTTP probe timeout per family |
| `AUDITOR_BATCH_CONCURRENCY` | `3` | Parallel sites audited during batch jobs |
| `AUDITOR_MAX_HOSTS_PER_SCAN` | `100` | Safety limit on distinct hosts probed per scan |
| `AUDITOR_MAX_REQUEST_BODY_BYTES` | `1048576` | Inbound payload limit (1 MiB) |

---

## Controlled Test Site

The project includes a controlled, deterministic mock site with intentional, seeded IPv6 and IPv4 failures (broken DNS, TCP timeout, SSL mismatch, HTTP 500) to validate classifier accuracy.

```bash
# Run the seeded detection regression tests
python3 -m pytest controlled-site/tests -q
```

---

## Test Suites

The project maintains rigorous test coverage across both backend and frontend suites:

```bash
# Run all Backend Tests (224 tests)
cd backend && .venv/bin/pytest

# Run all Frontend Tests (39 tests)
cd frontend && npm test -- --run

# Build Frontend for Production
cd frontend && npm run build
```

---

## Security Hardening

As audited in `docs/security-audit.md`:
- **SSRF Guard:** Rejects requests to loopback (`127.0.0.0/8`, `::1`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), and link-local addresses (`169.254.0.0/16`, `fe80::/10`).
- **Data Redaction:** Sensitive query parameters (`token`, `api_key`, `session`, `jwt`) and embedded credentials (`http://user:pass@host`) are stripped before writing reports.
- **Zero Cookies Policy:** Frontend and backend store no session or tracking cookies.

---

## Standards & Compliance

- **RFC 6555:** Happy Eyeballs: Success with Dual-Stack Hosts
- **RFC 8305:** Happy Eyeballs Version 2: Better Connectivity Using Concurrency
- **AIORI PS-027:** Internet Measurement & Dual-Stack Readiness Research

---

## License

This project is licensed under the [MIT License](LICENSE).
Distributed as an open research and diagnostic platform.
