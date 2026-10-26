"""``zapgate``: check ZAP JSON reports against a policy and write a Markdown summary."""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from datetime import date
from pathlib import Path

from zapgate.gate import Result, evaluate
from zapgate.policy import PolicyError, load_policy
from zapgate.report import RISKS, Alert, ReportError, load_reports


def to_markdown(result: Result, alerts: list[Alert], today: date) -> str:
    lines = ["## ZAP scan gate", "", f"**{'PASS' if result.passed else 'FAIL'}**", ""]
    counts = Counter(a.risk_name for a in alerts)
    lines.append("Alerts by risk: " + ", ".join(f"{r} {counts.get(r, 0)}" for r in reversed(RISKS)))
    lines.append("")
    if result.failing:
        lines += ["### Failing", "", "| Risk | Plugin | Alert | Example URL |", "|---|---|---|---|"]
        for f in sorted(result.failing, key=lambda f: -f.alert.risk):
            ex = f.instances[0]
            lines.append(
                f"| {f.alert.risk_name} | {f.alert.plugin_id} | {f.alert.name} | {ex.method} {ex.uri} ({len(f.instances)} total) |"
            )
        lines.append("")
    if result.allowed:
        lines += ["### Allowed by policy", "", "| Plugin | Alert | Reason | Expires |", "|---|---|---|---|"]
        for f in result.allowed:
            rule = f.allowed_by
            reason, expires = (rule.reason, str(rule.expires)) if rule else ("", "")
            lines.append(f"| {f.alert.plugin_id} | {f.alert.name} | {reason} | {expires} |")
        lines.append("")
    if result.expired_allows:
        lines.append("### Expired allowlist entries (no longer applied)")
        lines += [f"- plugin {a.plugin_id}: expired {a.expires} ({a.reason})" for a in result.expired_allows]
        lines.append("")
    if result.unused_allows:
        lines.append("### Allowlist entries that matched nothing (consider removing)")
        lines += [f"- plugin {a.plugin_id}: {a.reason}" for a in result.unused_allows]
        lines.append("")
    if result.below_threshold:
        lines += [
            "### Below the threshold (reported, not failing)",
            "",
            "| Risk | Plugin | Alert |",
            "|---|---|---|",
        ]
        seen: set[str] = set()
        for a in sorted(result.below_threshold, key=lambda a: -a.risk):
            if a.plugin_id + a.name not in seen:
                seen.add(a.plugin_id + a.name)
                lines.append(f"| {a.risk_name} | {a.plugin_id} | {a.name} |")
        lines.append("")
    lines.append(f"_Evaluated {today.isoformat()}._")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zapgate", description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path, help="ZAP JSON report files")
    parser.add_argument("--policy", type=Path, default=Path("zap/policy.toml"))
    parser.add_argument("--today", type=date.fromisoformat, default=None, help="override the date (tests)")
    args = parser.parse_args(argv)
    today = args.today or date.today()
    try:
        policy = load_policy(args.policy)
        alerts = load_reports(args.reports)
    except (PolicyError, ReportError, OSError) as exc:
        print(f"zapgate: {exc}", file=sys.stderr)
        return 2
    result = evaluate(alerts, policy, today)
    markdown = to_markdown(result, alerts, today)
    print(markdown)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(markdown)
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
