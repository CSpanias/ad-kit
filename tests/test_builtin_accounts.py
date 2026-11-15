import pytest

from ad_kit.checks import builtin_accounts

DOMAIN_SID = "S-1-5-21-1-2-3"


def test_builtin_accounts_are_queried_by_well_known_rid(monkeypatch):
    outputs = iter(
        [
            "WHOAMI 192.0.2.1 389 DC01 sAMAccountName: Administrator\n"
            "WHOAMI 192.0.2.1 389 DC01 Enabled: Yes\n"
            f"WHOAMI 192.0.2.1 389 DC01 User SID: {DOMAIN_SID}-500",
            "WHOAMI 192.0.2.1 389 DC01 sAMAccountName: Guest\n"
            "WHOAMI 192.0.2.1 389 DC01 Enabled: No\n"
            f"WHOAMI 192.0.2.1 389 DC01 User SID: {DOMAIN_SID}-501",
        ]
    )
    commands = []

    def fake_run_check(name, command, sensitive_values):
        commands.append(command)
        assert name in {"builtin-account-rid-500", "builtin-account-rid-501"}
        assert sensitive_values == ["password"]
        return next(outputs)

    monkeypatch.setattr(builtin_accounts, "run_check", fake_run_check)

    accounts, findings = builtin_accounts.builtin_accounts_check(
        "192.0.2.1",
        "user",
        "password",
    )

    assert accounts == {
        "administrator": {
            "rid": 500,
            "account_name": "Administrator",
            "enabled": True,
        },
        "guest": {
            "rid": 501,
            "account_name": "Guest",
            "enabled": False,
        },
    }
    assert [finding.id for finding in findings] == ["PRIV-004"]
    assert commands[0][-2:] == ["-o", "USER=Administrator"]
    assert commands[1][-2:] == ["-o", "USER=Guest"]


def test_enabled_guest_creates_finding_but_enabled_administrator_does_not(
    monkeypatch,
):
    outputs = iter(
        [
            "sAMAccountName: Administrator\nEnabled: Yes\n"
            f"User SID: {DOMAIN_SID}-500",
            "sAMAccountName: Guest\nEnabled: Yes\n"
            f"User SID: {DOMAIN_SID}-501",
        ]
    )
    loaded_findings = []

    monkeypatch.setattr(
        builtin_accounts,
        "run_check",
        lambda *_args, **_kwargs: next(outputs),
    )

    def fake_load_finding(category, finding_id):
        loaded_findings.append((category, finding_id))
        return builtin_accounts.Finding(
            id=finding_id,
            title=finding_id,
            commentary="",
            remediation="",
        )

    monkeypatch.setattr(builtin_accounts, "load_finding", fake_load_finding)

    accounts, findings = builtin_accounts.builtin_accounts_check(
        "192.0.2.1",
        "user",
        "password",
    )

    assert accounts["administrator"]["enabled"] is True
    assert accounts["guest"]["enabled"] is True
    assert [finding.id for finding in findings] == ["PRIV-004", "PRIV-003"]
    assert loaded_findings == [
        ("privileged_excessive", "PRIV-004"),
        ("privileged_excessive", "PRIV-003"),
    ]


@pytest.mark.parametrize(
    ("output", "expected_error"),
    [
        ("No entries found!", "Could not determine the status"),
        (
            "sAMAccountName: Administrator\nEnabled: Yes\n"
            f"User SID: {DOMAIN_SID}-501",
            "expected built-in account RID 500",
        ),
    ],
)
def test_builtin_accounts_fail_explicitly_for_invalid_results(
    monkeypatch,
    output,
    expected_error,
):
    monkeypatch.setattr(
        builtin_accounts,
        "run_check",
        lambda *_args, **_kwargs: output,
    )

    with pytest.raises(RuntimeError, match=expected_error):
        builtin_accounts.builtin_accounts_check(
            "192.0.2.1",
            "user",
            "password",
        )
