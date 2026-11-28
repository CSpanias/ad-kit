from contextlib import contextmanager, nullcontext
from types import SimpleNamespace

import pytest
from rich.console import Console
from rich.table import Table

from ad_kit.commands.checks import policy


@pytest.mark.parametrize(
    ("quota", "color_code"),
    [
        ("2", "31"),
        ("0", "32"),
    ],
)
def test_maq_quota_value_color(
    monkeypatch,
    quota,
    color_code,
):
    results = {
        "machine_account_quota": quota,
        "machine_join_group": "Authenticated Users",
        "machine_created": False,
        "machine_authenticated": False,
        "machine_deleted": False,
        "cleanup_method": "None",
        "machine_name": "ADKIT-TEST",
        "machine_password": "test-password",
    }
    printed = []

    @contextmanager
    def fake_progress(_message):
        yield

    def fake_print(*args, **kwargs):
        printed.append(args)

    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "192.0.2.1",
        "standard_user": "test-user",
    })
    monkeypatch.setattr(policy, "progress", fake_progress)
    monkeypatch.setattr(policy, "maq_check", lambda *_args: results)
    monkeypatch.setattr(policy, "load_finding", lambda *_args: SimpleNamespace(evidence=[]))
    monkeypatch.setattr(policy, "record_findings", lambda *_args: None)
    monkeypatch.setattr(policy.console, "print", fake_print)

    policy.run_maq_checks("test-password")

    tables = [args[0] for args in printed if args and isinstance(args[0], Table)]
    rendered = Console(
        record=True,
        force_terminal=True,
        color_system="standard",
    )
    rendered.print(tables[0])

    assert f"\x1b[{color_code}m{quota}\x1b[0m" in rendered.export_text(styles=True)


def test_maq_admin_cleanup_uses_ldap(monkeypatch):
    results = {
        "machine_account_quota": "10",
        "machine_join_group": "Authenticated Users",
        "machine_created": True,
        "machine_authenticated": True,
        "machine_deleted": False,
        "cleanup_method": "Domain Admin Required",
        "machine_name": "ADKIT-TEST",
        "machine_password": "machine-secret",
    }
    commands = []
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "192.0.2.1", "standard_user": "test-user",
    })
    monkeypatch.setattr(policy, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(policy, "maq_check", lambda *_args: results)
    monkeypatch.setattr(policy.typer, "confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(policy, "authenticate_domain_admin", lambda: ("admin", "admin-secret"))
    monkeypatch.setattr(
        policy, "cleanup_test_artifact",
        lambda name, command: commands.append((name, command)) or True,
    )
    monkeypatch.setattr(policy, "load_finding", lambda *_args: SimpleNamespace(evidence=[]))
    monkeypatch.setattr(policy, "record_findings", lambda *_args: None)

    policy.run_maq_checks("standard-secret")

    assert commands == [(
        "maq-delete-machine-da",
        [
            "nxc", "ldap", "192.0.2.1", "-u", "admin", "-p", "admin-secret",
            "-M", "add-computer", "-o", "NAME=ADKIT-TEST",
            "PASSWORD=machine-secret", "DELETE=True",
        ],
    )]
    assert results["machine_deleted"] is True
    assert results["cleanup_method"] == "Domain Administrator"


def test_maq_admin_cleanup_can_be_declined(monkeypatch):
    results = {
        "machine_account_quota": "10",
        "machine_join_group": "Authenticated Users",
        "machine_created": True,
        "machine_authenticated": True,
        "machine_deleted": False,
        "cleanup_method": "Domain Admin Required",
        "machine_name": "ADKIT-TEST",
        "machine_password": "machine-secret",
    }
    warnings = []
    findings = []
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "192.0.2.1", "standard_user": "test-user",
    })
    monkeypatch.setattr(policy, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(policy, "maq_check", lambda *_args: results)
    monkeypatch.setattr(policy.typer, "confirm", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        policy, "authenticate_domain_admin",
        lambda: pytest.fail("Declined cleanup must not request credentials"),
    )
    monkeypatch.setattr(
        policy, "cleanup_test_artifact",
        lambda *_args: pytest.fail("Declined cleanup must not run"),
    )
    monkeypatch.setattr(policy, "warn_test_artifact_remaining", lambda *args: warnings.append(args))
    monkeypatch.setattr(policy, "load_finding", lambda *_args: SimpleNamespace(evidence=[]))
    monkeypatch.setattr(policy, "record_findings", lambda entries: findings.extend(entries))

    policy.run_maq_checks("standard-secret")

    assert results["machine_deleted"] is False
    assert results["cleanup_method"] == "Manual Intervention Required"
    assert warnings == [("machine account", "ADKIT-TEST$", "maq-create-machine")]
    assert len(findings) == 1
    assert any("manual remediation" in item for item in findings[0].evidence)
