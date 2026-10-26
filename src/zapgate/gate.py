"""Apply a policy to alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from zapgate.policy import Allow, Policy
from zapgate.report import Alert, Instance


@dataclass
class Finding:
    alert: Alert
    instances: list[Instance]
    allowed_by: Allow | None = None


@dataclass
class Result:
    failing: list[Finding] = field(default_factory=list)
    allowed: list[Finding] = field(default_factory=list)
    below_threshold: list[Alert] = field(default_factory=list)
    expired_allows: list[Allow] = field(default_factory=list)
    unused_allows: list[Allow] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failing


def evaluate(alerts: list[Alert], policy: Policy, today: date) -> Result:
    result = Result()
    active = [a for a in policy.allow if a.expires >= today]
    result.expired_allows = [a for a in policy.allow if a.expires < today]
    used: set[int] = set()

    for alert in alerts:
        if alert.risk < policy.fail_on or alert.confidence < policy.min_confidence:
            result.below_threshold.append(alert)
            continue
        instances = list(alert.instances) or [Instance(uri="", method="")]
        not_allowed: list[Instance] = []
        allowed_here: list[Instance] = []
        rule: Allow | None = None
        for inst in instances:
            match = next((a for a in active if a.matches(alert.plugin_id, inst.uri)), None)
            if match is None:
                not_allowed.append(inst)
            else:
                allowed_here.append(inst)
                used.add(id(match))
                rule = match
        if not_allowed:
            result.failing.append(Finding(alert, not_allowed))
        if allowed_here:
            result.allowed.append(Finding(alert, allowed_here, allowed_by=rule))

    result.unused_allows = [a for a in active if id(a) not in used]
    return result
