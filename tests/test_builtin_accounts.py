import pytest

from ad_kit.checks import builtin_accounts
from ad_kit.core.exceptions import CheckExecutionError

DOMAIN_SID = "S-1-5-21-1-2-3"


@pytest.mark.parametrize("admin_name", ["Admin", "Renamed Admin"])
def test_builtin_accounts_resolve_renamed_accounts_by_sid(monkeypatch, admin_name):
    calls = []

    def run(name, command, sensitive_values):
        calls.append((name, command))
        assert sensitive_values == ["password"]
        if name == "builtin-account-domain-sid":
            return f"Domain SID: {DOMAIN_SID}"
        if name.startswith("builtin-account-lookup"):
            return (
                f"sAMAccountName: {admin_name}"
                if name.endswith("500") else "sAMAccountName: Guest"
            )
        if name.endswith("500"):
            return f"sAMAccountName: {admin_name}\nEnabled: Yes\nUser SID: {DOMAIN_SID}-500"
        return f"sAMAccountName: Guest\nEnabled: No\nUser SID: {DOMAIN_SID}-501"

    monkeypatch.setattr(builtin_accounts, "run_check", run)
    accounts, findings = builtin_accounts.builtin_accounts_check(
        "192.0.2.1", "example.test", "user", "password"
    )
    assert accounts["administrator"]["account_name"] == admin_name
    assert accounts["administrator"]["enabled"] is True
    assert accounts["guest"]["enabled"] is False
    assert [finding.id for finding in findings] == ["PRIV-004"]
    assert "name other than the default `Administrator`" in findings[0].commentary
    assert "well-known relative identifier (RID)" in findings[0].commentary
    assert "with RID 500" in findings[0].evidence[0]
    assert "relative identifier" not in findings[0].evidence[0]
    assert "Consider disabling" in findings[0].remediation
    assert "renaming" not in findings[0].remediation
    assert calls[1][1][-3:] == [f"{DOMAIN_SID}-500", "--attr", "sAMAccountName"]
    assert calls[2][1][-1] == f"USER={admin_name}"
    assert calls[3][1][-3:] == [f"{DOMAIN_SID}-501", "--attr", "sAMAccountName"]


@pytest.mark.parametrize("account_name", ["Administrator", "administrator"])
def test_builtin_administrator_default_name_retains_rename_guidance(monkeypatch, account_name):
    def run(name, _command, sensitive_values):
        if name == "builtin-account-domain-sid":
            return f"Domain SID: {DOMAIN_SID}"
        if name == "builtin-account-lookup-500":
            return f"sAMAccountName: {account_name}"
        if name == "builtin-account-rid-500":
            return f"sAMAccountName: {account_name}\nEnabled: Yes\nUser SID: {DOMAIN_SID}-500"
        if name == "builtin-account-lookup-501":
            return "sAMAccountName: Guest"
        return f"sAMAccountName: Guest\nEnabled: No\nUser SID: {DOMAIN_SID}-501"

    monkeypatch.setattr(builtin_accounts, "run_check", run)
    _, findings = builtin_accounts.builtin_accounts_check(
        "dc", "example.test", "user", "password"
    )
    assert "name other than the default `Administrator`" not in findings[0].commentary
    assert "Consider renaming or disabling" in findings[0].remediation
    assert "relative identifier (RID) 500" in findings[0].evidence[0]


@pytest.mark.parametrize("failure", ["lookup", "status"])
def test_empty_builtin_account_name_is_incomplete(monkeypatch, failure):
    incomplete = []
    monkeypatch.setattr(
        builtin_accounts, "record_incomplete", lambda *args: incomplete.append(args)
    )

    def run(name, _command, sensitive_values):
        if name == "builtin-account-domain-sid":
            return f"Domain SID: {DOMAIN_SID}"
        if name == "builtin-account-lookup-500":
            return "sAMAccountName:  " if failure == "lookup" else "sAMAccountName: Admin"
        if name == "builtin-account-rid-500":
            return f"sAMAccountName:  \nEnabled: Yes\nUser SID: {DOMAIN_SID}-500"
        if name == "builtin-account-lookup-501":
            return "sAMAccountName: Guest"
        return f"sAMAccountName: Guest\nEnabled: No\nUser SID: {DOMAIN_SID}-501"

    monkeypatch.setattr(builtin_accounts, "run_check", run)
    accounts, findings = builtin_accounts.builtin_accounts_check(
        "dc", "example.test", "user", "password"
    )
    assert accounts["administrator"]["enabled"] is None
    assert findings == []
    assert len(incomplete) == 1


@pytest.mark.parametrize("failure", ["lookup", "wrong_sid", "wrong_domain", "missing_status"])
def test_failed_builtin_account_does_not_hide_other_account(monkeypatch, failure):
    incomplete = []
    monkeypatch.setattr(
        builtin_accounts, "record_incomplete", lambda *args: incomplete.append(args)
    )

    def run(name, _command, sensitive_values):
        if name == "builtin-account-domain-sid":
            return f"Domain SID: {DOMAIN_SID}"
        if name == "builtin-account-lookup-500":
            if failure == "lookup":
                raise CheckExecutionError(name, [], returncode=1)
            return "sAMAccountName: Administrator"
        if name == "builtin-account-rid-500":
            if failure == "missing_status":
                return "sAMAccountName: Administrator"
            if failure == "wrong_domain":
                return "sAMAccountName: Administrator\nEnabled: Yes\nUser SID: S-1-5-21-9-8-7-500"
            return f"sAMAccountName: Administrator\nEnabled: Yes\nUser SID: {DOMAIN_SID}-1691"
        if name == "builtin-account-lookup-501":
            return "sAMAccountName: Guest"
        return f"sAMAccountName: Guest\nEnabled: Yes\nUser SID: {DOMAIN_SID}-501"

    monkeypatch.setattr(builtin_accounts, "run_check", run)
    accounts, findings = builtin_accounts.builtin_accounts_check(
        "dc", "example.test", "user", "password"
    )
    assert accounts["administrator"]["enabled"] is None
    assert accounts["guest"]["enabled"] is True
    assert [finding.id for finding in findings] == ["PRIV-003"]
    assert "security identifier (SID)" in findings[0].commentary
    assert "relative identifier (RID) 501" in findings[0].evidence[0]
    assert len(incomplete) == 1 and f"{DOMAIN_SID}-500" in incomplete[0]


@pytest.mark.parametrize("output", ["No SID", f"User SID: {DOMAIN_SID}-500"])
def test_missing_domain_sid_marks_both_accounts_unknown(monkeypatch, output):
    incomplete = []
    monkeypatch.setattr(
        builtin_accounts, "record_incomplete", lambda *args: incomplete.append(args)
    )
    monkeypatch.setattr(builtin_accounts, "run_check", lambda *_args, **_kwargs: output)
    accounts, findings = builtin_accounts.builtin_accounts_check(
        "dc", "example.test", "user", "password"
    )
    assert all(account["enabled"] is None for account in accounts.values())
    assert not findings and len(incomplete) == 1
