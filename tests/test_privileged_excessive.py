import pytest

from ad_kit.checks import privileged_excessive
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.privileged import PRIVILEGED_GROUPS
from ad_kit.reporting.html import render_html
from ad_kit.reporting.markdown import format_findings


def _entry(name, admin_count=None):
    prefix = "LDAP 192.0.2.1 389 DC01 "
    lines = [
        f"{prefix}[+] Response for object: CN={name},DC=example",
        f"{prefix}sAMAccountName       {name}",
    ]
    if admin_count is not None:
        lines.append(f"{prefix}adminCount           {admin_count}")
    return "\n".join(lines)


@pytest.mark.parametrize(("protected", "finding_expected"), [(25, True), (24, False)])
def test_admin_count_uses_enabled_user_population(monkeypatch, protected, finding_expected):
    monkeypatch.setattr(privileged_excessive, "require_session", lambda: {
        "excluded_users": ["TEST USER"],
    })
    monkeypatch.setattr(
        privileged_excessive,
        "get_privileged_group_members",
        lambda *_args: {group: [] for group in PRIVILEGED_GROUPS},
    )
    output = "\n".join([
        _entry(f"account-{index}", 1 if index < protected else None)
        for index in range(100)
    ] + [_entry("Test User", 1)])
    calls = []

    def fake_run_check(name, command, sensitive_values):
        calls.append(name)
        assert name == "privileged-enabled-users"
        assert command[-3:] == [
            "--query",
            "(&(sAMAccountType=805306368)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            "sAMAccountName adminCount",
        ]
        assert sensitive_values == ["password"]
        return output

    monkeypatch.setattr(privileged_excessive, "run_check", fake_run_check)
    results, findings = privileged_excessive.privileged_excessive_check("dc", "user", "password")

    assert calls == ["privileged-enabled-users"]
    assert results["enabled_users"] == 100
    assert results["admin_count"] == {
        "member_count": protected,
        "percentage": float(protected),
        "members": sorted(f"account-{index}" for index in range(protected)),
    }
    assert [finding.id for finding in findings] == (["PRIV-002"] if finding_expected else [])
    if finding_expected:
        assert "25 enabled user accounts" in findings[0].evidence[1]


@pytest.mark.parametrize(("count", "noun"), [(1, "account"), (2, "accounts")])
def test_admin_count_report_uses_correct_account_form(monkeypatch, count, noun):
    monkeypatch.setattr(privileged_excessive, "require_session", lambda: {})
    monkeypatch.setattr(
        privileged_excessive, "get_privileged_group_members",
        lambda *_args: {group: [] for group in PRIVILEGED_GROUPS},
    )
    monkeypatch.setattr(
        privileged_excessive, "run_check",
        lambda *_args, **_kwargs: "\n".join(_entry(f"user-{i}", 1) for i in range(count)),
    )
    _, findings = privileged_excessive.privileged_excessive_check("dc", "user", "password")
    finding = next(finding for finding in findings if finding.id == "PRIV-002")
    sentence = f"The `adminCount=1` attribute was set on {count} enabled user {noun},"
    assert sentence in finding.evidence[1]
    assert sentence in format_findings([finding])
    assert sentence in render_html([finding])
    assert f"contained {count} enabled user {noun}" in finding.evidence[0]


def test_enabled_user_parser_preserves_names_and_zero_admin_count():
    output = "\n".join([_entry("Service Account", 1), _entry("Other", 0)])
    assert privileged_excessive._enabled_user_accounts(output, set()) == {
        "Service Account": True, "Other": False,
    }


@pytest.mark.parametrize("output", [
    "",
    "LDAP dc 389 DC [-] LDAP search failed",
    "LDAP dc 389 DC [+] Response for object: CN=bad,DC=example",
    _entry("alice", "invalid"),
    _entry("alice") + "\n" + _entry("ALICE"),
    _entry("alice") + "\nLDAP dc 389 DC adminCount",
    _entry("alice") + "\nLDAP dc 389 DC [-] sizeLimitExceeded",
])
def test_enabled_user_parser_rejects_incomplete_output(output):
    with pytest.raises(CheckExecutionError):
        privileged_excessive._enabled_user_accounts(output, set())


def test_enabled_user_parser_rejects_all_users_excluded():
    with pytest.raises(CheckExecutionError, match="No enabled users"):
        privileged_excessive._enabled_user_accounts(_entry("alice"), {"alice"})
