import time

from core import modules, password_health
from core.models import Entry, SecretType


def test_primary_groups_are_mutually_exclusive_and_findings_overlap():
    now = time.time()
    otp = modules.new_module(modules.OTP)
    entries = [
        Entry(id="a", password="short", updated_at=now),
        Entry(id="b", password="short", updated_at=now),
        Entry(id="c", password="Correct-Horse-Battery-Staple!", updated_at=now,
              fields=modules.fields_with_modules({}, [otp])),
    ]
    report = password_health.analyze(entries, force=True, now=now, common_password_check=lambda _: False)
    assert report.total == len(report.high_risk) + len(report.improvement) + len(report.healthy)
    assert len(report.findings["duplicate"]) == 2
    assert len(report.findings["too_short"]) == 2
    assert len(report.high_risk) == 2
    assert len(report.healthy) == 1


def test_module_password_long_unchanged():
    now = time.time()
    password = modules.new_module(modules.PASSWORD)
    password["value"] = "M0dule!Only#Credential2026"
    entry = Entry(
        id="module", title="Server", secret_type=SecretType.LOGIN,
        updated_at=now - 200 * 86400,
        fields=modules.fields_with_modules({}, [password]),
    )
    report = password_health.analyze([entry], force=True, now=now, common_password_check=lambda _: False)
    assert report.total == 1
    assert entry in report.findings["long_unchanged"]
    assert report.improvement == (entry,)


def test_common_default_is_separate_from_online_leak_result():
    now = time.time()
    entry = Entry(id="common", password="vendor-default", updated_at=now)
    report = password_health.analyze(
        [entry], force=True, now=now, common_password_check=lambda value: value == "vendor-default"
    )
    assert report.findings["pattern"] == (entry,)
    assert report.findings["leaked"] == ()


def test_finding_copy_matches_the_rule_evidence():
    unchanged = password_health.FINDING_BY_KEY["long_unchanged"]
    assert "条目" in unchanged.label
    assert "不等同于密码一定未更换" in unchanged.description

    leaked = password_health.FINDING_BY_KEY["leaked"]
    assert "联网" in leaked.description
    assert "公开泄露" in leaked.label
