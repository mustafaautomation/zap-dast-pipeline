"""Parse ZAP's traditional JSON report (``-J report.json`` in the packaged scans)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

RISKS = ("informational", "low", "medium", "high")


@dataclass(frozen=True)
class Instance:
    uri: str
    method: str


@dataclass(frozen=True)
class Alert:
    plugin_id: str
    name: str
    risk: int  # 0 informational .. 3 high
    confidence: int  # 0 false positive .. 4 user confirmed
    cwe: str
    instances: tuple[Instance, ...] = field(default_factory=tuple)
    source: str = ""

    @property
    def risk_name(self) -> str:
        return RISKS[self.risk]


class ReportError(ValueError):
    """The file is not a ZAP JSON report."""


def _int(value: object, what: str) -> int:
    try:
        return int(str(value))
    except ValueError as exc:
        raise ReportError(f"{what} is not a number: {value!r}") from exc


def parse_report(data: dict[str, object], source: str = "") -> list[Alert]:
    sites = data.get("site")
    if not isinstance(sites, list):
        raise ReportError("missing 'site' list; expected ZAP's traditional JSON report")
    alerts: list[Alert] = []
    for site in sites:
        if not isinstance(site, dict):
            raise ReportError("site entry is not an object")
        for raw in site.get("alerts", []):
            risk = _int(raw.get("riskcode"), "riskcode")
            if not 0 <= risk <= 3:
                raise ReportError(f"riskcode out of range: {risk}")
            instances = tuple(
                Instance(uri=str(i.get("uri", "")), method=str(i.get("method", "")))
                for i in raw.get("instances", [])
            )
            alerts.append(
                Alert(
                    plugin_id=str(raw.get("pluginid", "")),
                    name=str(raw.get("alert") or raw.get("name") or ""),
                    risk=risk,
                    confidence=_int(raw.get("confidence", 2), "confidence"),
                    cwe=str(raw.get("cweid", "")),
                    instances=instances,
                    source=source,
                )
            )
    return alerts


def load_reports(paths: list[Path]) -> list[Alert]:
    alerts: list[Alert] = []
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReportError(f"{path}: not valid JSON ({exc})") from exc
        if not isinstance(data, dict):
            raise ReportError(f"{path}: top level is not an object")
        alerts.extend(parse_report(data, source=path.name))
    return alerts
