from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from ad_kit.checks import dns, maq, passwords
from ad_kit.commands.checks import policy
from ad_kit.core.checks import duration_to_minutes
from ad_kit.core.exceptions import CheckExecutionError


@contextmanager
def no_progress(_message):
    yield


def test_unknown_policy_is_not_reported_as_weak(monkeypatch):
    monkeypatch.setattr(passwords, "run_check", lambda *_args: "Domain Password Complex: unexpected")
    parsed = passwords.password_policy_check("dc", "user", "password")
    assert set(passwords.password_policy_assessment(parsed).values()) == {passwords.UNKNOWN}
    findings = []
    monkeypatch.setattr(policy, "require_session", lambda: {"dc_ip": "dc", "standard_user": "user"})
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(policy, "password_policy_check", lambda *_args: parsed)
    monkeypatch.setattr(policy, "record_findings", findings.extend)
    policy.run_password_policy_checks("password")
    assert findings == []


def test_mixed_policy_reports_only_known_weaknesses(monkeypatch):
    output = (
        "Minimum password length: 8\n"
        "Password history length: invalid\n"
        "Minimum password age: 1 day\n"
        "Maximum password age: 42 days\n"
        "Domain Password Complex: 1\n"
        "Reset Account Lockout Counter: 1 hour\n"
        "Locked Account Duration: unexpected\n"
        "Account Lockout Threshold: 5\n"
    )
    monkeypatch.setattr(passwords, "run_check", lambda *_args: output)
    parsed = passwords.password_policy_check("dc", "user", "password")
    assessed = passwords.password_policy_assessment(parsed)
    assert assessed["minimum_length"].startswith("[red]")
    assert assessed["password_history"] == passwords.UNKNOWN
    assert assessed["lockout_duration"] == passwords.UNKNOWN
    assert assessed["minimum_age"].startswith("[green]")
    assert assessed["observation_window"].startswith("[green]")
    assert duration_to_minutes("1 day 2 hours 1 minute") == 1561
    assert duration_to_minutes("1 day2 hours") is None

    findings = []
    monkeypatch.setattr(policy, "require_session", lambda: {"dc_ip": "dc", "standard_user": "user"})
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(policy, "password_policy_check", lambda *_args: parsed)
    monkeypatch.setattr(policy, "load_finding", lambda *_args: SimpleNamespace(commentary="Remediation"))
    monkeypatch.setattr(policy, "record_findings", findings.extend)
    policy.run_password_policy_checks("password")
    assert len(findings) == 1
    assert "Minimum password length" in findings[0].commentary
    assert "Password history" not in findings[0].commentary
    assert "lockout duration" not in findings[0].commentary


@pytest.mark.parametrize("failed_step", ["maq-auth-machine", "maq-delete-machine"])
def test_machine_failure_warns_and_propagates(monkeypatch, failed_step):
    monkeypatch.setattr(maq.secrets, "token_hex", lambda size: "a" * size)
    warnings = []
    monkeypatch.setattr(maq, "warn_test_artifact_remaining", lambda *args: warnings.append(args))

    def run(name, _command):
        if name == failed_step:
            raise CheckExecutionError(name, [], stderr="failed")
        return {"maq": "MachineAccountQuota: 10", "maq-create-machine": "Successfully added",
                "maq-auth-machine": "[+]"}[name]

    monkeypatch.setattr(maq, "run_check", run)
    with pytest.raises(CheckExecutionError):
        maq.maq_check("dc", "user", "password")
    assert warnings == [("machine account", "ADKIT-AAAA$", "maq-create-machine")]


def test_unconfirmed_machine_deletion_attempts_admin_cleanup(monkeypatch):
    monkeypatch.setattr(maq.secrets, "token_hex", lambda size: "a" * size)
    warnings = []
    monkeypatch.setattr(maq, "warn_test_artifact_remaining", lambda *args: warnings.append(args))
    output = {"maq": "MachineAccountQuota: 10", "maq-create-machine": "Successfully added",
              "maq-auth-machine": "[+]", "maq-delete-machine": "unexpected output"}
    monkeypatch.setattr(maq, "run_check", lambda name, _command: output[name])
    assert maq.maq_check("dc", "user", "password")["cleanup_method"] == "Domain Admin Required"
    assert warnings == [("machine account", "ADKIT-AAAA$", "maq-create-machine")]


@pytest.mark.parametrize("remove_output", ["error", "unconfirmed"])
def test_dns_unconfirmed_cleanup_warns(monkeypatch, remove_output):
    monkeypatch.setattr(dns.secrets, "token_hex", lambda _size: "abcd")
    monkeypatch.setattr(dns, "load_finding", lambda *_args: SimpleNamespace(evidence=[]))
    warnings = []
    monkeypatch.setattr(dns, "warn_test_artifact_remaining", lambda *args: warnings.append(args))

    def run(name, _command):
        if name == "dns-record-create":
            return "Successfully added"
        if remove_output == "error":
            raise CheckExecutionError(name, [], stderr="failed")
        return "unexpected output"

    monkeypatch.setattr(dns, "run_check", run)
    if remove_output == "error":
        with pytest.raises(CheckExecutionError):
            dns.dns_record_creation_check("dc", "example.test", "user", "password")
    else:
        results, _ = dns.dns_record_creation_check("dc", "example.test", "user", "password")
        assert results["cleanup_method"] == "Domain Admin Required"
    assert warnings == [("DNS record", "ad-kit-abcd.example.test", "dns-record-create")]


def test_warning_contains_evidence_without_password(monkeypatch):
    from ad_kit.core import checks
    warnings = []
    monkeypatch.setattr(checks, "print_warning", warnings.append)
    checks.warn_test_artifact_remaining("machine account", "ADKIT-TEST$", "maq-create-machine")
    assert "ADKIT-TEST$" in warnings[0]
    assert "maq-create-machine.txt" in warnings[0]
    assert "password" not in warnings[0].lower()


@pytest.mark.parametrize("kind", ["machine", "dns"])
@pytest.mark.parametrize("cleanup", ["error", "unconfirmed"])
def test_admin_cleanup_failure_warns(monkeypatch, kind, cleanup):
    session = {"dc_ip": "dc", "domain": "example.test", "standard_user": "user"}
    monkeypatch.setattr(policy, "require_session", lambda: session)
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(policy, "authenticate_domain_admin", lambda: ("admin", "secret"))
    monkeypatch.setattr(policy, "record_findings", lambda _findings: None)
    monkeypatch.setattr(policy, "load_finding", lambda *_args: SimpleNamespace(evidence=[]))
    warnings = []
    monkeypatch.setattr(policy, "warn_test_artifact_remaining", lambda *args: warnings.append(args))

    def cleanup_artifact(name, _command):
        if cleanup == "error":
            raise CheckExecutionError(name, [], stderr="failed")
        return False

    monkeypatch.setattr(policy, "cleanup_test_artifact", cleanup_artifact)
    if kind == "machine":
        results = {
            "machine_account_quota": "10", "machine_join_group": "users",
            "machine_created": True, "machine_authenticated": True,
            "machine_deleted": False, "cleanup_method": "Domain Admin Required",
            "machine_name": "ADKIT-TEST", "machine_password": "secret",
        }
        monkeypatch.setattr(policy, "maq_check", lambda *_args: results)
        run = policy.run_maq_checks
        expected = ("machine account", "ADKIT-TEST$", "maq-create-machine")
    else:
        results = {
            "dns_record_creation": True, "record_name": "ad-kit-test.example.test",
            "record_ip": "192.0.2.1", "record_deleted": False,
            "cleanup_method": "Domain Admin Required",
        }
        monkeypatch.setattr(policy, "dns_record_creation_check", lambda *_args: (results, []))
        run = policy.run_dns_checks
        expected = ("DNS record", "ad-kit-test.example.test", "dns-record-create")

    if cleanup == "error":
        with pytest.raises(CheckExecutionError):
            run("password")
    else:
        run("password")
        assert results["cleanup_method"] == "Manual Intervention Required"
    assert warnings == [expected]
