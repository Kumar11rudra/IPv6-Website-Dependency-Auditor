#!/usr/bin/env bash
# Generates a throwaway self-signed cert covering every controlled-test.example
# hostname, for local/dev use only. On the real VPS, use a real certificate
# (e.g. Let's Encrypt) for each hostname instead.
set -euo pipefail
cd "$(dirname "$0")"
DOMAIN="${1:-controlled-test.example}"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout dev.key -out dev.crt -days 30 \
  -subj "/CN=${DOMAIN}" \
  -addext "subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN}"
echo "wrote dev.crt / dev.key for ${DOMAIN} and *.${DOMAIN}"
