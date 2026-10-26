"""Fail unless every required ZAP plugin ID appears in the reports (used by the negative CI job)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from zapgate.report import load_reports


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--require", nargs="+", required=True, help="plugin IDs that must be present")
    args = parser.parse_args()
    found = {a.plugin_id for a in load_reports(args.reports)}
    missing = [p for p in args.require if p not in found]
    print(f"found plugin IDs: {', '.join(sorted(found))}")
    if missing:
        print(f"missing expected alerts: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
