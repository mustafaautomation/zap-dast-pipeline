#!/usr/bin/env bash
# Run ZAP's packaged full scan (spider, passive and active rules against the HTML pages) and
# API scan (OpenAPI import, active rules against the JSON API) on localhost:8000.
# Reports are written to ./reports. -I: let zapgate decide pass/fail.
set -euo pipefail
IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
mkdir -p reports && chmod 777 reports
docker run --rm --network host -v "$PWD/reports:/zap/wrk:rw" "$IMAGE" \
  zap-full-scan.py -t http://localhost:8000/ -J full.json -r full.html -m 1 -T 10 -I
docker run --rm --network host -v "$PWD/reports:/zap/wrk:rw" "$IMAGE" \
  zap-api-scan.py -t http://localhost:8000/openapi.json -f openapi -J api.json -r api.html -I
