# zap-dast-pipeline

[![CI](https://github.com/mustafaautomation/zap-dast-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/mustafaautomation/zap-dast-pipeline/actions/workflows/ci.yml)

Dynamic application security testing (DAST) with OWASP ZAP in GitHub Actions, plus a small
policy gate (`zapgate`) that decides whether the build passes. The scan target is a small
FastAPI "notes" app that lives in this repo.

This is a personal portfolio project, not production or client work. The target app exists only
to be scanned.

## What CI does

Three jobs run on every push, pull request and weekly (Mondays, to pick up new ZAP rules):

| Job | What it proves |
|---|---|
| Lint, types and unit tests | ruff (including the `S` security rules), mypy strict, pytest with at least 85% coverage of `zapgate` and the app |
| ZAP scans, hardened app | ZAP finds nothing at Low risk or above that the policy does not explicitly accept, so the gate exits 0 |
| ZAP scans, insecure mode | The same scans against the app started with `NOTES_INSECURE=1` (no security headers, a search page that reflects raw input). The gate **must** exit 1, and the reports must contain plugins 10038 (no CSP), 10020 (no anti-clickjacking header), 10021 (no `nosniff`) and 40012 (reflected XSS). If ZAP stops finding planted problems, this job goes red |

The negative job is the point of the repo: a security gate that never fails is indistinguishable
from one that is broken.

Each scan job runs two packaged ZAP scans from the `ghcr.io/zaproxy/zaproxy:stable` image
(`scripts/zap-scan.sh`):

- `zap-full-scan.py` against `http://localhost:8000/`: spider, passive rules and active rules on
  the HTML pages. The index links to `/search?q=welcome` so the spider reaches the search page.
- `zap-api-scan.py` against `/openapi.json`: imports the OpenAPI document and runs active rules
  on the JSON API. The HTML routes are left out of the OpenAPI document on purpose, because the
  API scan raises an alert for any non-JSON response.

Both write JSON and HTML reports, which are uploaded as workflow artifacts (`zap-reports-*`).
A full CI run takes about 3 minutes.

## The gate: zapgate

```
uv run zapgate reports/full.json reports/api.json --policy zap/policy.toml
```

- Reads ZAP's traditional JSON report format and merges alerts across reports.
- Fails on alerts at or above `fail_on` (currently `low`) with confidence at or above
  `min_confidence` (currently 1, so only alerts ZAP marked as false positives are skipped).
- `[[allow]]` entries accept a specific plugin, optionally limited to a URI regex. Each one needs a
  reason of at least 10 characters and an `expires` date. Expired entries stop applying and are
  listed, so accepted risks come back for review instead of living forever.
- Writes a markdown summary to stdout and to the GitHub job summary, listing failing, allowed,
  below-threshold, expired and unused entries.
- Exit codes: 0 pass, 1 gate failed, 2 bad input (unreadable report or invalid policy).

### What is currently accepted, and why

`zap/policy.toml` has two entries, both pinned to the localhost CI target and expiring 30 April 2027:

| Plugin | Alert | Reason |
|---|---|---|
| 10106 | HTTP Only Site | CI serves the app over plain HTTP on localhost, so there is no HTTPS listener to find. A real deployment would terminate TLS at a proxy and should be scanned there |
| 100001 | Unexpected Content-Type | The API scan probes the site root, which is the HTML page, not JSON. The full scan covers that page |

The first scans also found real issues that were fixed in the app rather than allowlisted. For
example, ZAP's Cookie Slack Detector (90027) correctly noticed that the hardened app's `session`
cookie had no effect, so the cookie was removed.

## What the insecure scan finds

From a CI run on 26 October 2026, the insecure app produced these alerts (Low and above):
reflected XSS (40012) and DOM XSS (40026), both High; missing CSP (10038), missing anti-clickjacking
header (10020) and HTTP-only site (10106), all Medium; missing `nosniff` (10021), missing
Permissions-Policy (10063), missing COEP/COOP/CORP (90004), Cookie Slack Detector (90027) and
Unexpected Content-Type (100001), all Low. Results can change as ZAP's rules change, which is why
the negative job only requires four specific plugins.

## Run it locally

You need [uv](https://docs.astral.sh/uv/) and, for the scans, Docker.

```
uv sync
uv run pytest                     # unit tests
scripts/start-app.sh              # hardened app on :8000 (scripts/start-app.sh insecure for the other mode)
scripts/zap-scan.sh               # writes reports/full.json and reports/api.json
uv run zapgate reports/full.json reports/api.json --policy zap/policy.toml
```

## Layout

```
src/notes_app/     FastAPI target app (security headers middleware, JSON API, two HTML pages)
src/zapgate/       report parser, policy loader, gate logic, CLI
zap/policy.toml    gate thresholds and accepted findings
scripts/           start the app, run the ZAP scans, check required alerts
tests/             unit tests; tests/fixtures/sample-report.json is a hand-written ZAP report
.github/workflows/ci.yml
```

## Limits

- ZAP is a black-box scanner. A clean scan means ZAP's rules found nothing, not that the app is
  secure. There is no authenticated scanning here because the app has no authentication.
- The active scans use ZAP's default policies and a 10-minute cap on the full scan. They run
  against a throwaway local app; never point active scans at systems you do not own.
- ZAP rule IDs and risk levels come from the ZAP version in the `stable` image at the time of the
  run, so a new ZAP release can change results. The weekly run is there to catch that.

## License

MIT
