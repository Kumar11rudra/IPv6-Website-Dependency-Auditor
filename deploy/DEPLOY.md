# Deploying the controlled test site to the dual-stack VPS

Per the project's confirmed decisions: the controlled site is deployed publicly on the
same dual-stack VPS that runs the scanner, and final PS-027 measurements use this public
deployment, not the local Docker fallback.

## 1. Prerequisites on the VPS
- A domain you control (examples below use `controlled-test.example` - replace with yours).
- The VPS has both a public IPv4 address and a public IPv6 address/subnet, confirmed
  reachable: `curl -4 ifconfig.me` and `curl -6 ifconfig.me` should each return an address.
- Ports 80 and 443 free (or use different local ports and a reverse proxy - not covered here
  for simplicity, matching the project's "do not over-engineer" instruction).

## 2. DNS records to create
| Hostname                                   | A (IPv4)        | AAAA (IPv6)      | Notes                          |
|---------------------------------------------|-----------------|------------------|--------------------------------|
| `controlled-test.example`                   | VPS IPv4        | VPS IPv6         | root document, dual-stack      |
| `static.controlled-test.example`            | VPS IPv4        | VPS IPv6         | CSS/JS/logo, dual-stack        |
| `v4only-img.controlled-test.example`        | VPS IPv4        | *(none - omit)*  | deliberately no AAAA           |
| `v6-tcp-fail.controlled-test.example`       | VPS IPv4        | VPS IPv6         | AAAA advertised, TCP refused   |
| `v6-tls-fail.controlled-test.example`       | VPS IPv4        | VPS IPv6         | AAAA advertised, TLS broken    |
| `v6-http-fail.controlled-test.example`      | VPS IPv4        | VPS IPv6         | AAAA advertised, HTTP 500      |

All the "advertised but broken" hostnames use the SAME VPS IPv6 address as everything
else in DNS. What differs is what's actually listening on that address for that specific
port/hostname context - see step 4.

## 3. Real certificates
Use a real certificate covering all the `https` hostnames above (e.g. via `certbot` with
DNS-01 or HTTP-01 validation for each name, or one cert with all of them as SANs). Do NOT
use `controlled-site/server/dev.crt` in production - it is a throwaway, unpinned, 30-day
self-signed cert meant only for local dev (see `server/gen_certs.sh`).

## 4. Running the origins
`seed_server.py` already implements every failure mode from `seeded.json` (see its own
`--help`). Because DNS now sends the SAME IPv6 address to three different "broken" hostnames
plus the working ones, and HTTP name-based virtual hosting can't change *transport-layer*
behaviour (TCP/TLS happen before the Host header is even read), the cleanest approach on
a single VPS is:

**Give each seeded hostname its own distinct public IPv6 address** (a /64 from your provider
gives 2^64 of these - ask for a few extra routed addresses, or use `ip -6 addr add` to add
secondary addresses to the VPS's interface), and run one `seed_server.py` process per
hostname, each bound to that hostname's own dedicated IPv6 address:

```bash
# example: four processes, four distinct IPv6 addresses on the same VPS
python3 server/seed_server.py --content-dir content \
  --v4-bind <VPS_IPV4>:80  --v6-bind <VPS_IPV6_A>:80  --v6-mode pass &

python3 server/seed_server.py --content-dir content \
  --v4-bind <VPS_IPV4>:8081 --v6-bind <VPS_IPV6_B>:443 --v6-mode tcp_fail \
  --scheme https --cert /etc/letsencrypt/live/controlled-test.example/fullchain.pem \
  --key  /etc/letsencrypt/live/controlled-test.example/privkey.pem &
# (tcp_fail doesn't actually open the v6 listener, so --scheme/--cert here are unused for
#  the v6 side, but the v4 side still serves the site normally over HTTPS)

python3 server/seed_server.py --content-dir content \
  --v4-bind <VPS_IPV4>:8082 --v6-bind <VPS_IPV6_C>:443 --v6-mode tls_fail \
  --scheme https --cert ... --key ... &

python3 server/seed_server.py --content-dir content \
  --v4-bind <VPS_IPV4>:8083 --v6-bind <VPS_IPV6_D>:443 --v6-mode http_fail \
  --scheme https --cert ... --key ... &
```
Then point each hostname's AAAA record at that process's dedicated IPv6 address (its A
record can all point at the same VPS IPv4 address, on different ports, or you can also give
each an extra IPv4 alias - either works since the IPv4 path is always meant to pass).

Run these under `systemd` (one `.service` unit per process) rather than raw `&` background
jobs for anything long-lived; a minimal unit file just wraps the command above with
`Restart=always`.

## 5. `v4only-img` needs no server changes
It's just DNS: create the A record, do not create an AAAA record. Any normal web server on
the VPS's IPv4 address serving `content/images/photo.png` satisfies this - `seed_server.py`
with no `--v6-bind` does this automatically (see `origin-v4only` in the Docker fallback for
the equivalent).

## 6. Verify before running the 30-site batch
```bash
dig +short AAAA v4only-img.controlled-test.example     # must be EMPTY
dig +short AAAA v6-tcp-fail.controlled-test.example     # must return the dedicated address
curl -6 --max-time 5 https://v6-tcp-fail.controlled-test.example/   # must FAIL (refused)
curl -4 --max-time 5 https://v6-tcp-fail.controlled-test.example/   # must SUCCEED
```
Then run the scanner against `https://controlled-test.example/` and confirm its findings
match `seeded.json` exactly - this is the acceptance test for the whole controlled site.
