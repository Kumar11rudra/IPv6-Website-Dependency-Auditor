# Controlled IPv4-only test site (PS-027 requirement 2)

A small site with deliberately seeded dependencies that are IPv4-only, or advertise IPv6
in DNS while being broken at a specific stage (TCP / TLS / HTTP). Used to prove the
scanner detects exactly what's seeded, at the correct failure stage - see `seeded.json`
for the full manifest of expected outcomes, and
`tests/test_seeded_detection.py` for the automated proof that the scanner's classifier
(from `../backend/app/scanner/`) gets every one of them right.

| Hostname | DNS | Expected IPv6 outcome |
|---|---|---|
| `controlled-test.example` | dual-stack | `IPv6_REACHABLE` |
| `static.controlled-test.example` | dual-stack | `IPv6_REACHABLE` |
| `v4only-img.controlled-test.example` | A only | `DNS_FAILURE` |
| `v6-tcp-fail.controlled-test.example` | dual-stack | `TCP_FAILURE` |
| `v6-tls-fail.controlled-test.example` | dual-stack | `TLS_FAILURE` |
| `v6-http-fail.controlled-test.example` | dual-stack | `HTTP_FAILURE` |

## Layout
- `content/` - the actual HTML/CSS/JS/image/font/API files served.
- `server/seed_server.py` - one small server whose IPv4 and IPv6 listening addresses can
  behave DIFFERENTLY, which is what lets a single hostname's IPv6 path fail at a specific,
  chosen stage without touching DNS. See its module docstring for the four modes.
- `server/gen_certs.sh` - generates a throwaway self-signed cert for local dev/testing only.
- `docker/` - local development fallback (Docker + dnsmasq). **Not used for final
  measurements** - see `docker/README.md`.
- `../deploy/DEPLOY.md` - how this site is actually deployed publicly on the dual-stack VPS,
  which is what real PS-027 measurements are run against.
- `tests/test_seeded_detection.py` - runs `seed_server.py` for real (as a subprocess) and
  feeds it through the actual scanner classifier, asserting every seeded failure is detected
  correctly. Run with `python3 -m pytest controlled-site/tests -q` from the repo root (needs
  the backend's dependencies installed - see `../README.md`).

## Honest limitation
This dev/test environment has no real IPv6, so `test_seeded_detection.py` simulates the
"IPv6 path" with a second IPv4 loopback address rather than a real IPv6 address. The
per-address branching logic in `seed_server.py` and the scanner's classifier are both
address-family-agnostic, so this genuinely exercises the detection logic end to end - but
the final, authoritative proof is running this same site with real AAAA records against
the scanner on the dual-stack VPS, per `../deploy/DEPLOY.md` step 6.
