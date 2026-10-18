# Local development fallback

This reproduces the controlled site's five hostnames locally using Docker, for
building/testing the site itself. **Final PS-027 measurements must use the public
VPS deployment** (see `../deploy/DEPLOY.md`), not this fallback, per the project's
Phase 1 decision: a scanner without real IPv6 egress cannot produce a real IPv6
finding, and a laptop's local Docker network is not a substitute for the public
internet an actual browser and DNS resolver would see.

## Requirements
- Docker with IPv6 enabled on the daemon. Add to `/etc/docker/daemon.json`:
  ```json
  { "ipv6": true, "fixed-cidr-v6": "fd00:d0c5::/64" }
  ```
  then restart Docker (`sudo systemctl restart docker`).

## Run
```bash
cd controlled-site/docker
docker compose up --build
```
This starts five origin containers (one per seeded failure mode, see `dnsmasq/dnsmasq.conf`
for exactly which hostname maps to which container) plus a `dnsmasq` container that answers
DNS for `*.controlled-test.example` inside the compose network.

## Point the scanner (or your own browser) at it
Either:
- run the scanner's own container on the same `controlled` Docker network and point its
  resolver at the `dns` service (`172.28.0.2`), or
- add the dnsmasq container's IP as a resolver on your host and query `controlled-test.example`
  directly (Linux: add `nameserver 172.28.0.2` to a resolver config scoped to this network;
  exact steps vary by OS and are intentionally not scripted here since this is a dev-only
  fallback, not a supported deployment target).

## What this does NOT prove
Docker's user-defined bridge network assigns each container a real, working IPv6 address,
so `origin-pass`'s dual-stack behaviour is genuinely exercised. But this is all on a private
`fd00::/8` ULA range - it says nothing about whether the scanning HOST (the machine running
`docker compose`) itself has real IPv6 internet egress, which is what Phase 2's
`GET /api/context` reports on and what a real scan run needs. Use this fallback to verify the
site's and scanner's LOGIC; use the VPS to produce real, reportable measurements.
