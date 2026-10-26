#!/usr/bin/env bash
# Run ZAP's packaged baseline (passive, spider) and API (OpenAPI, active) scans against the
# app on localhost:8000. Reports are written to ./reports. -I: let zapgate decide pass/fail.
set -euo pipefail
IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
mkdir -p reports && chmod 777 reports
docker run --rm --network host -v "$PWD/reports:/zap/wrk:rw" "$IMAGE" \
  zap-baseline.py -t http://localhost:8000/ -J baseline.json -r baseline.html -m 1 -I
docker run --rm --network host -v "$PWD/reports:/zap/wrk:rw" "$IMAGE" \
  zap-api-scan.py -t http://localhost:8000/openapi.json -f openapi -J api.json -r api.html -I
