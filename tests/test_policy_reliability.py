import io
import subprocess
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from rich.console import Console

from ad_kit.checks import dns, maq, passwords
from ad_kit.commands.checks import policy
from ad_kit.core import checks
from ad_kit.core.checks import duration_to_minutes
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.reporting.html import render_html
from ad_kit.reporting.markdown import format_finding_sections


@contextmanager
def no_progress(_message):
    yield


@pytest.mark.parametrize("kind", ["maq", "dns"])
def test_current_command_evidence_includes_cleanup_without_replaying(
    monkeypatch, tmp_path, kind
):
    output = io.StringIO()
    commands = []
    monkeypatch.setattr(policy, "console", Console(file=output, width=200))
    monkeypatch.setattr(policy, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
    })
    monkeypatch.setattr(policy, "authenticate_domain_admin", lambda: ("admin", "admin-secret"))
    monkeypatch.setattr(policy, "record_findings", lambda _findings: None)
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(checks, "progress", no_progress)
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(maq.secrets, "token_hex", lambda length: "f" * length)

    def fake_run(command, **_kwargs):
        commands.append(command)
        if kind == "maq":
            if "maq" in command:
                result = "MachineAccountQuota: 10"
            elif "smb" in command:
                result = "[+] machine authenticated"
            elif "DELETE=True" in command:
                result = "successfully deleted" if "admin" in command else "delete denied"
            else:
                result = "successfully added"
        elif "dnsDump" in command:
            result = (
                "recordName: unrelated.example.test\nA: 203.0.113.1\n\n"
                "recordName: ad-kit-ffff.example.test\nA: 192.0.2.1\n"
            )
        elif "add" in command:
            result = "successfully added"
        else:
            result = "successfully removed" if "admin" in command else "remove denied"
        return subprocess.CompletedProcess(command, 0, stdout=result, stderr="")

    monkeypatch.setattr(checks.subprocess, "run", fake_run)
    if kind == "maq":
        policy.run_maq_checks("standard-secret")
        assert len(commands) == 5
    else:
        policy.run_dns_checks("standard-secret")
        assert len(commands) == 4

    text = output.getvalue()
    assert text.count("$ ") == len(commands)
    assert "successfully added" in text
    assert "successfully deleted" in text if kind == "maq" else "successfully removed" in text
    assert "standard-secret" not in text and "admin-secret" not in text
    assert "ffffffffffffffff" not in text
    assert "[REDACTED]" in text
    if kind == "dns":
        assert "recordName: ad-kit-ffff.example.test" in text
        assert "unrelated.example.test" not in text
        assert [command[-2:] for command in commands[:3]] == [
            ["ad-kit-ffff", "192.0.2.1"], ["get", "dnsDump"],
            ["ad-kit-ffff", "192.0.2.1"],
        ]
    assert text.count("\n\n$ ") == len(commands) - 1
    assert text.endswith("\n\n")


def test_maq_without_finding_does_not_display_evidence(monkeypatch, tmp_path):
    output = io.StringIO()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "maq-create-machine.txt").write_text("STALE", encoding="utf-8")
    monkeypatch.setattr(policy, "console", Console(file=output, width=200))
    monkeypatch.setattr(policy, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user",
    })
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(checks, "progress", no_progress)
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        checks.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout="MachineAccountQuota: 0", stderr=""
        ),
    )
    policy.run_maq_checks("secret")
    assert "Machine Account Quota - Command Evidence" not in output.getvalue()
    assert "STALE" not in output.getvalue()
    assert "MachineAccountQuota: 0" in (evidence_dir / "maq.txt").read_text()


def test_dns_without_finding_does_not_display_evidence(monkeypatch, tmp_path):
    output = io.StringIO()
    monkeypatch.setattr(policy, "console", Console(file=output, width=200))
    monkeypatch.setattr(policy, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
    })
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(checks, "progress", no_progress)
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        checks.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout="access denied", stderr=""
        ),
    )
    policy.run_dns_checks("secret")
    assert "DNS Record Creation - Command Evidence" not in output.getvalue()
    assert "access denied" in (tmp_path / "evidence" / "dns-record-create.txt").read_text()


@pytest.mark.parametrize("confirmation", [
    "recordName: ad-kit-abcd.example.test\nA: 203.0.113.1",
    "recordName: ad-kit-abcd-other.example.test\nA: 192.0.2.1",
    "recordName: ad-kit-abcd.example.test",
    "command failed",
])
def test_unconfirmed_dns_record_still_gets_cleaned_up(monkeypatch, confirmation):
    calls = []
    incomplete = []
    monkeypatch.setattr(dns.secrets, "token_hex", lambda _size: "abcd")
    monkeypatch.setattr(dns, "record_incomplete", lambda *args: incomplete.append(args))

    def run(name, _command):
        calls.append(name)
        if name == "dns-record-create":
            return "Successfully added"
        if name == "dns-record-confirm":
            if confirmation == "command failed":
                raise CheckExecutionError(name, [], returncode=1)
            return confirmation
        return "Successfully removed"

    monkeypatch.setattr(dns, "run_check", run)
    result, findings = dns.dns_record_creation_check("dc", "example.test", "user", "secret")
    assert calls == ["dns-record-create", "dns-record-confirm", "dns-record-remove"]
    assert result["record_deleted"] and findings
    assert len(incomplete) == 1
    assert not any("DNS dump confirmed" in entry or "resolved to" in entry
                   for entry in findings[0].evidence)


def test_dns_confirmation_requires_exact_name_and_address():
    excerpt, confirmed = dns.dns_confirmation_excerpt(
        "recordName: ad-kit-abcd.example.test\nA: 203.0.113.1\n\n"
        "recordName: other.example.test\nA: 192.0.2.1",
        "ad-kit-abcd.example.test", "192.0.2.1",
    )
    assert not confirmed
    assert "other.example.test" not in excerpt


def test_dns_confirmation_interruption_still_attempts_cleanup(monkeypatch):
    calls = []
    monkeypatch.setattr(dns.secrets, "token_hex", lambda _size: "abcd")

    def run(name, _command):
        calls.append(name)
        if name == "dns-record-create":
            return "Successfully added"
        if name == "dns-record-confirm":
            raise KeyboardInterrupt
        return "Successfully removed"

    monkeypatch.setattr(dns, "run_check", run)
    with pytest.raises(KeyboardInterrupt):
        dns.dns_record_creation_check("dc", "example.test", "user", "secret")
    assert calls == ["dns-record-create", "dns-record-confirm", "dns-record-remove"]


def test_unknown_policy_is_not_reported_as_weak(monkeypatch):
    monkeypatch.setattr(passwords, "run_check", lambda *_args: "Domain Password Complex: unexpected")
    parsed = passwords.password_policy_check("dc", "user", "password")
    assert set(passwords.password_policy_assessment(parsed).values()) == {passwords.UNKNOWN}
    findings = []
    monkeypatch.setattr(policy, "require_session", lambda: {"dc_ip": "dc", "standard_user": "user"})
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(policy, "password_policy_check", lambda *_args: parsed)
    monkeypatch.setattr(policy, "record_findings", findings.extend)
    incomplete = []
    monkeypatch.setattr(policy, "record_incomplete", lambda *args: incomplete.append(args))
    policy.run_password_policy_checks("password")
    assert findings == []
    assert len(incomplete) == 1
    assert "minimum length" in incomplete[0][2]


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
    monkeypatch.setattr(policy, "record_findings", findings.extend)
    incomplete = []
    monkeypatch.setattr(policy, "record_incomplete", lambda *args: incomplete.append(args))
    policy.run_password_policy_checks("password")
    assert len(findings) == 1
    assert "Minimum password length" in findings[0].commentary
    assert "Password history" not in findings[0].commentary
    assert "lockout duration" not in findings[0].commentary
    assert "minimum password length" in findings[0].remediation
    assert "password history" not in findings[0].remediation
    assert len(findings[0].references) == 2
    assert any("minimum-password-length" in url for url in findings[0].references)
    assert all("lockout" not in url for url in findings[0].references)
    assert "password history" in incomplete[0][2]
    assert "lockout duration" in incomplete[0][2]
    assert "minimum-password-length" in format_finding_sections(findings[0])["Remediation"]
    assert "minimum-password-length" in render_html(findings)


@pytest.mark.parametrize("maximum_age", ["42 days", "Not Set", "unexpected", None])
def test_maximum_age_is_not_assessed_or_displayed(monkeypatch, maximum_age):
    output = io.StringIO()
    raw_policy = (
        "Minimum password length: 14\n"
        "Password history length: 5\n"
        "Minimum password age: 1 day\n"
        "Domain Password Complex: 1\n"
        "Reset Account Lockout Counter: 30 minutes\n"
        "Locked Account Duration: 30 minutes\n"
        "Account Lockout Threshold: 5\n"
    )
    if maximum_age is not None:
        raw_policy += f"Maximum password age: {maximum_age}\n"
    monkeypatch.setattr(passwords, "run_check", lambda *_args: raw_policy)
    monkeypatch.setattr(policy, "console", Console(file=output, width=120))
    monkeypatch.setattr(policy, "print_section", lambda _title: None)
    monkeypatch.setattr(policy, "require_session", lambda: {"dc_ip": "dc", "standard_user": "user"})
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(
        policy, "record_findings", lambda _findings: pytest.fail("unexpected finding")
    )
    monkeypatch.setattr(policy, "record_incomplete", lambda *_args: pytest.fail("unexpected gap"))

    parsed = passwords.password_policy_check("dc", "user", "password")
    assert "maximum_age" not in parsed
    assert "maximum_age" not in passwords.password_policy_assessment(parsed)
    policy.run_password_policy_checks("password")
    assert "Maximum Age" not in output.getvalue()
    assert "Minimum Age" in output.getvalue()


def _assess_policy(**overrides):
    values = {
        "minimum_length": "12",
        "password_history": "5",
        "minimum_age": "1 day",
        "complexity": "Enabled",
        "observation_window": "30 minutes",
        "lockout_duration": "30 minutes",
        "lockout_threshold": "5",
    }
    values.update(overrides)
    return values, passwords.password_policy_assessment(values)


def _run_policy(monkeypatch, values):
    findings, incomplete = [], []
    monkeypatch.setattr(policy, "require_session", lambda: {"dc_ip": "dc", "standard_user": "user"})
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(policy, "password_policy_check", lambda *_args: values)
    monkeypatch.setattr(policy, "record_findings", findings.extend)
    monkeypatch.setattr(policy, "record_incomplete", lambda *args: incomplete.append(args))
    policy.run_password_policy_checks("password")
    return findings, incomplete


def test_multiple_weak_settings_get_only_relevant_guidance_and_deduplicated_references(monkeypatch):
    values, _ = _assess_policy(minimum_length="8", complexity="Disabled")
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not incomplete
    assert len(findings) == 1
    finding = findings[0]
    assert "Minimum password length was 8" in finding.commentary
    assert "complexity requirement was Disabled" in finding.commentary
    assert "blocklists" in finding.remediation
    assert "lockout threshold" not in finding.remediation
    assert len(finding.references) == len(set(finding.references)) == 3


def test_zero_lockout_threshold_does_not_flag_inactive_settings(monkeypatch):
    values, assessed = _assess_policy(
        lockout_threshold="0", lockout_duration="0 minutes", observation_window="0 minutes",
    )
    assert "Not applicable" in assessed["lockout_duration"]
    assert "Not applicable" in assessed["observation_window"]
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not incomplete
    assert len(findings) == 1
    assert "disabling account lockout" in findings[0].commentary
    assert "lockout duration" not in findings[0].commentary
    assert "observation window" not in findings[0].remediation


def test_manual_unlock_is_not_automatically_weak(monkeypatch):
    values, assessed = _assess_policy(lockout_duration="0 minutes")
    assert "Manual unlock" in assessed["lockout_duration"]
    findings, incomplete = _run_policy(monkeypatch, values)
    assert findings == []
    assert incomplete == []


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [("5", "Review (not set)"), ("0", "Not applicable"), ("Unknown", "Unknown")],
)
def test_netexec_not_set_lockout_duration_respects_threshold(monkeypatch, threshold, expected):
    values, assessed = _assess_policy(lockout_duration="Not Set", lockout_threshold=threshold)
    assert expected in assessed["lockout_duration"]
    _, incomplete = _run_policy(monkeypatch, values)
    if threshold in {"Unknown", "5"}:
        assert "lockout duration" in incomplete[0][2]
    else:
        assert not incomplete


def test_netexec_not_set_lockout_duration_is_parsed_for_review(monkeypatch):
    output = (
        "LDAP dc 389 DC Locked Account Duration: Not Set\n"
        "LDAP dc 389 DC Account Lockout Threshold: 5\n"
    )
    monkeypatch.setattr(passwords, "run_check", lambda *_args: output)
    parsed = passwords.password_policy_check("dc", "user", "password")
    assert parsed["lockout_duration"] == "Not Set"
    assert "Review (not set)" in passwords.password_policy_assessment(parsed)["lockout_duration"]


def test_minimum_age_below_baseline_reports_actual_value(monkeypatch):
    values, assessed = _assess_policy(minimum_age="30 minutes")
    assert assessed["minimum_age"].startswith("[red]")
    findings, _ = _run_policy(monkeypatch, values)
    assert "Minimum password age was 30 minutes" in findings[0].commentary
    assert any("minimum-password-age" in url for url in findings[0].references)


@pytest.mark.parametrize(
    ("setting", "value", "commentary", "reference"),
    [
        ("password_history", "1", "Password history retained 1", "enforce-password-history"),
        ("observation_window", "10 minutes", "observation window was 10 minutes", "reset-account-lockout-counter-after"),
        ("lockout_duration", "10 minutes", "lockout duration was 10 minutes", "account-lockout-duration"),
        ("lockout_threshold", "11", "lockout threshold was 11", "account-lockout-threshold"),
    ],
)
def test_each_weak_setting_has_specific_guidance(monkeypatch, setting, value, commentary, reference):
    values, _ = _assess_policy(**{setting: value})
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not incomplete
    assert len(findings) == 1
    assert commentary in findings[0].commentary
    assert any(reference in url for url in findings[0].references)


def test_unknown_lockout_threshold_does_not_assume_lockout_is_enabled(monkeypatch):
    values, assessed = _assess_policy(
        lockout_threshold="Unknown", lockout_duration="10 minutes", observation_window="10 minutes",
    )
    assert assessed["lockout_threshold"] == passwords.UNKNOWN
    assert assessed["lockout_duration"] == passwords.UNKNOWN
    assert assessed["observation_window"] == passwords.UNKNOWN
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not findings
    assert len(incomplete) == 1
    assert all(setting in incomplete[0][2] for setting in (
        "lockout threshold", "lockout duration", "observation window",
    ))


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
