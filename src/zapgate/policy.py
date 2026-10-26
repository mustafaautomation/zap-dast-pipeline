"""The gate policy: a severity threshold plus an allowlist where every entry has a reason
and an expiry date, so accepted risks are reviewed again instead of living forever."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from zapgate.report import RISKS


class PolicyError(ValueError):
    """The policy file is invalid."""


@dataclass(frozen=True)
class Allow:
    plugin_id: str
    reason: str
    expires: date
    uri_pattern: re.Pattern[str] | None = None

    def matches(self, plugin_id: str, uri: str) -> bool:
        if plugin_id != self.plugin_id:
            return False
        return self.uri_pattern is None or bool(self.uri_pattern.search(uri))


@dataclass(frozen=True)
class Policy:
    fail_on: int  # minimum risk that fails the gate
    min_confidence: int  # alerts below this confidence are reported but never fail
    allow: tuple[Allow, ...]


def _risk(name: object) -> int:
    if not isinstance(name, str) or name.lower() not in RISKS:
        raise PolicyError(f"fail_on must be one of {', '.join(RISKS)}, got {name!r}")
    return RISKS.index(name.lower())


def parse_policy(data: dict[str, object]) -> Policy:
    gate = data.get("gate", {})
    if not isinstance(gate, dict):
        raise PolicyError("[gate] must be a table")
    fail_on = _risk(gate.get("fail_on", "medium"))
    min_conf = gate.get("min_confidence", 1)
    if not isinstance(min_conf, int) or not 0 <= min_conf <= 4:
        raise PolicyError("min_confidence must be an integer 0-4")

    entries = data.get("allow", [])
    if not isinstance(entries, list):
        raise PolicyError("[[allow]] entries must be an array of tables")
    allow: list[Allow] = []
    for i, entry in enumerate(entries):
        where = f"allow[{i}]"
        if not isinstance(entry, dict):
            raise PolicyError(f"{where} must be a table")
        plugin_id, reason, expires = entry.get("plugin_id"), entry.get("reason"), entry.get("expires")
        if not isinstance(plugin_id, str) or not plugin_id.isdigit():
            raise PolicyError(f"{where}.plugin_id must be a numeric string")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise PolicyError(f"{where}.reason must explain the decision (10+ characters)")
        if not isinstance(expires, date):
            raise PolicyError(f"{where}.expires must be a TOML date, e.g. 2027-01-31")
        pattern = entry.get("uri_regex")
        if pattern is not None and not isinstance(pattern, str):
            raise PolicyError(f"{where}.uri_regex must be a string")
        try:
            compiled = re.compile(pattern) if pattern else None
        except re.error as exc:
            raise PolicyError(f"{where}.uri_regex is invalid: {exc}") from exc
        allow.append(Allow(plugin_id=plugin_id, reason=reason.strip(), expires=expires, uri_pattern=compiled))
    return Policy(fail_on=fail_on, min_confidence=min_conf, allow=tuple(allow))


def load_policy(path: Path) -> Policy:
    with path.open("rb") as fh:
        return parse_policy(tomllib.load(fh))
