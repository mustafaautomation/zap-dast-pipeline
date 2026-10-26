import json
from datetime import date
from pathlib import Path

import pytest

from zapgate import cli
from zapgate.gate import evaluate
from zapgate.policy import PolicyError, parse_policy
from zapgate.report import ReportError, load_reports, parse_report

FIXTURES = Path(__file__).parent / "fixtures"
TODAY = date(2026, 10, 26)


@pytest.fixture
def alerts() -> list:
    return load_reports([FIXTURES / "sample-report.json"])


def policy(fail_on: str = "low", allow: list[dict] | None = None, min_confidence: int = 1):
    return parse_policy(
        {"gate": {"fail_on": fail_on, "min_confidence": min_confidence}, "allow": allow or []}
    )


def test_parse_report(alerts: list) -> None:
    assert [a.plugin_id for a in alerts] == ["10038", "10049", "10021", "40012"]
    csp = alerts[0]
    assert csp.risk == 2 and csp.risk_name == "medium" and csp.confidence == 3 and csp.cwe == "693"
    assert [i.uri for i in csp.instances] == ["http://localhost:8000/", "http://localhost:8000/search?q=a"]


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"site": "x"},
        {"site": [1]},
        {"site": [{"alerts": [{"riskcode": "nine"}]}]},
        {"site": [{"alerts": [{"riskcode": "7"}]}]},
    ],
)
def test_rejects_non_zap_reports(data: dict) -> None:
    with pytest.raises(ReportError):
        parse_report(data)


def test_threshold_low_fails_on_low_and_medium(alerts: list) -> None:
    result = evaluate(alerts, policy("low"), TODAY)
    assert not result.passed
    assert sorted(f.alert.plugin_id for f in result.failing) == ["10021", "10038"]


def test_threshold_medium_reports_low_without_failing(alerts: list) -> None:
    result = evaluate(alerts, policy("medium"), TODAY)
    assert [f.alert.plugin_id for f in result.failing] == ["10038"]
    assert {a.plugin_id for a in result.below_threshold} == {"10049", "10021", "40012"}


def test_false_positive_confidence_never_fails(alerts: list) -> None:
    result = evaluate(alerts, policy("high"), TODAY)
    assert result.passed  # the only high alert has confidence 0 (false positive)


def test_allow_entry_with_uri_regex_covers_only_matching_instances(alerts: list) -> None:
    allow = [
        {
            "plugin_id": "10038",
            "uri_regex": r"/search",
            "reason": "search page CSP tracked in ticket 12",
            "expires": date(2027, 1, 31),
        }
    ]
    result = evaluate(alerts, policy("medium", allow), TODAY)
    assert len(result.failing) == 1
    assert [i.uri for i in result.failing[0].instances] == ["http://localhost:8000/"]
    assert [i.uri for i in result.allowed[0].instances] == ["http://localhost:8000/search?q=a"]


def test_allow_entry_without_regex_covers_the_plugin(alerts: list) -> None:
    allow = [
        {"plugin_id": "10038", "reason": "accepted for the demo deployment", "expires": date(2027, 1, 31)}
    ]
    assert evaluate(alerts, policy("medium", allow), TODAY).passed


def test_expired_allow_entry_stops_applying(alerts: list) -> None:
    allow = [
        {"plugin_id": "10038", "reason": "accepted for the demo deployment", "expires": date(2026, 10, 25)}
    ]
    result = evaluate(alerts, policy("medium", allow), TODAY)
    assert not result.passed
    assert [a.plugin_id for a in result.expired_allows] == ["10038"]


def test_allow_entry_expiring_today_still_applies(alerts: list) -> None:
    allow = [{"plugin_id": "10038", "reason": "accepted for the demo deployment", "expires": TODAY}]
    assert evaluate(alerts, policy("medium", allow), TODAY).passed


def test_unused_allow_entries_are_reported(alerts: list) -> None:
    allow = [
        {"plugin_id": "90022", "reason": "old exception for error disclosure", "expires": date(2027, 1, 1)}
    ]
    result = evaluate(alerts, policy("medium", allow), TODAY)
    assert [a.plugin_id for a in result.unused_allows] == ["90022"]


@pytest.mark.parametrize(
    "data",
    [
        {"gate": {"fail_on": "critical"}},
        {"gate": {"min_confidence": 9}},
        {"allow": [{"plugin_id": "abc", "reason": "long enough reason", "expires": date(2027, 1, 1)}]},
        {"allow": [{"plugin_id": "10038", "reason": "short", "expires": date(2027, 1, 1)}]},
        {"allow": [{"plugin_id": "10038", "reason": "long enough reason", "expires": "2027-01-01"}]},
        {
            "allow": [
                {
                    "plugin_id": "10038",
                    "reason": "long enough reason",
                    "expires": date(2027, 1, 1),
                    "uri_regex": "(",
                }
            ]
        },
    ],
)
def test_invalid_policies(data: dict) -> None:
    with pytest.raises(PolicyError):
        parse_policy(data)


def test_repo_policy_loads() -> None:
    from zapgate.policy import load_policy

    p = load_policy(Path(__file__).parents[1] / "zap" / "policy.toml")
    assert p.fail_on == 1 and p.allow == ()


def test_cli_exit_codes_and_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    pol = tmp_path / "policy.toml"
    pol.write_text('[gate]\nfail_on = "medium"\n')
    assert (
        cli.main([str(FIXTURES / "sample-report.json"), "--policy", str(pol), "--today", "2026-10-26"]) == 1
    )
    out = capsys.readouterr().out
    assert "**FAIL**" in out and "Content Security Policy (CSP) Header Not Set" in out
    assert "**FAIL**" in summary.read_text()

    pol.write_text('[gate]\nfail_on = "high"\n')
    assert cli.main([str(FIXTURES / "sample-report.json"), "--policy", str(pol)]) == 0


def test_cli_bad_input_is_exit_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not": "zap"}))
    assert cli.main([str(bad), "--policy", str(Path(__file__).parents[1] / "zap" / "policy.toml")]) == 2
    assert cli.main([str(tmp_path / "missing.json")]) == 2
