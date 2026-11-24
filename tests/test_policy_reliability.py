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


@pytest.fixture(autouse=True)
def stub_optional_fgpp_by_default(monkeypatch):
    monkeypatch.setattr(policy.typer, "confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(policy, "authenticate_domain_admin", lambda: ("admin", "test-secret"))
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: ([], None))
    monkeypatch.setattr(policy, "resultant_password_policy", lambda *_args: None)


@pytest.mark.parametrize("kind", ["maq", "dns"])
def test_current_command_evidence_includes_cleanup_without_replaying(
    monkeypatch, tmp_path, kind
):
    output = io.StringIO()
    commands = []
    recorded = []
    monkeypatch.setattr(policy, "console", Console(file=output, width=200))
    monkeypatch.setattr(policy, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
    })
    monkeypatch.setattr(policy, "authenticate_domain_admin", lambda: ("admin", "admin-secret"))
    monkeypatch.setattr(policy, "record_findings", recorded.extend)
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
    assert len(recorded) == 1
    sections = format_finding_sections(recorded[0])
    assert "### Evidence\n\n" in sections["Commentary"]
    assert "Evidence" not in sections
    assert "<h3>Evidence</h3>" in render_html(recorded)


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
    monkeypatch.setattr(policy, "record_incomplete", lambda *args, **_kwargs: incomplete.append(args))
    policy.run_password_policy_checks("password")
    return findings, incomplete


def _pso_output(*, count=1, applies_to=None, minimum_age="1 days", minimum_length="25"):
    lines = [
        f"{count} PSO Objects found!",
        "Policy Name: Strong policy",
        f"Minimum Password Length: {minimum_length}",
        "Minimum Password History Length: 3",
        "Lockout Threshold: 0",
        "Observation Window: 30 minutes",
        "Lockout Duration: 30 minutes",
        "Complexity Enabled: TRUE",
        "Reversible Encryption: FALSE",
        f"Minimum Password Age: {minimum_age}",
        "Precedence: 1 (Lower is Higher Priority)",
        "Policy Applies to:",
    ]
    lines.extend(applies_to or [])
    return "\n".join(f"LDAP dc 389 DC {line}" for line in lines)


def _query_output(*lines):
    return "\n".join(f"LDAP dc 389 DC {line}" for line in lines)


@pytest.mark.parametrize(("account", "attribute", "escaped"), [
    ("EXAMPLE\\us*er", "sAMAccountName", r"us\2aer"),
    ("user@example.test", "userPrincipalName", "user@example.test"),
])
def test_resultant_policy_query_identifies_user_and_escapes_filter(
    monkeypatch, account, attribute, escaped
):
    calls = []
    expected_account = account.rsplit("\\", 1)[-1]
    dn = "CN=Policy,CN=Password Settings Container,CN=System,DC=example,DC=test"

    def run(name, command, **kwargs):
        calls.append((name, command, kwargs))
        return _query_output(
            "[+] Response for object: CN=User,DC=example,DC=test",
            f"{attribute} {expected_account}",
            f"msDS-ResultantPSO {dn}",
        )

    monkeypatch.setattr(passwords, "run_check", run)
    assert passwords.resultant_password_policy("dc", "admin", "secret", account) == dn
    assert f"({attribute}={escaped})" in calls[0][1][-2]
    assert calls[0][2]["sensitive_values"] == ["secret"]


@pytest.mark.parametrize("output", [
    "",
    _query_output("[-] LDAP search failed"),
    _query_output("[+] Response for object: CN=User,DC=example", "sAMAccountName other"),
    _query_output("[+] Response for object: CN=User,DC=example", "sAMAccountName user",
                  "msDS-ResultantPSO"),
    _query_output("[+] Response for object: CN=User,DC=example", "sAMAccountName user",
                  "msDS-ResultantPSO CN=one,DC=example",
                  "msDS-ResultantPSO CN=two,DC=example"),
    _query_output("[+] Response for object: CN=one,DC=example", "sAMAccountName user",
                  "[+] Response for object: CN=two,DC=example", "sAMAccountName user"),
])
def test_resultant_policy_query_rejects_unverified_results(monkeypatch, output):
    monkeypatch.setattr(passwords, "run_check", lambda *_args, **_kwargs: output)
    with pytest.raises(CheckExecutionError):
        passwords.resultant_password_policy("dc", "admin", "secret", "user")


def test_resultant_policy_query_presumes_default_only_for_identified_user(monkeypatch):
    monkeypatch.setattr(
        passwords, "run_check",
        lambda *_args, **_kwargs: _query_output(
            "[+] Response for object: CN=User,DC=example", "sAMAccountName USER",
        ),
    )
    assert passwords.resultant_password_policy("dc", "admin", "secret", "user") is None


def test_resultant_policy_matches_full_dn_and_rejects_duplicate_names(monkeypatch):
    first = "CN=Policy,CN=Password Settings Container,CN=System,DC=example"
    other = "CN=Policy,OU=Other,DC=example"
    output = _query_output(f"[+] Response for object: {first}", "name Policy")
    monkeypatch.setattr(passwords, "run_check", lambda *_args, **_kwargs: output)
    assert passwords.resultant_policy_name("dc", "admin", "secret", first.lower()) == "Policy"
    output += "\n" + _query_output(f"[+] Response for object: {other}", "name Policy")
    with pytest.raises(CheckExecutionError):
        passwords.resultant_policy_name("dc", "admin", "secret", first)


def test_resultant_policy_is_reported_even_when_assignments_were_not_returned(monkeypatch):
    output = io.StringIO()
    calls = []
    dn = "CN=Strong policy,CN=Password Settings Container,CN=System,DC=example,DC=test"

    def run(name, _command, **kwargs):
        calls.append((name, kwargs))
        if name == "password-policy-fine-grained":
            return _pso_output()
        if name == "password-policy-resultant":
            return _query_output(
                "[+] Response for object: CN=User,DC=example,DC=test",
                "sAMAccountName user", f"msDS-ResultantPSO {dn}",
            )
        if name == "password-policy-resultant-pso":
            return _query_output(f"[+] Response for object: {dn}", "name Strong policy")
        pytest.fail(f"Unexpected check: {name}")

    monkeypatch.setattr(policy, "console", Console(file=output, width=160))
    monkeypatch.setattr(passwords, "run_check", run)
    monkeypatch.setattr(policy, "fine_grained_password_policies", passwords.fine_grained_password_policies)
    monkeypatch.setattr(policy, "resultant_password_policy", passwords.resultant_password_policy)
    monkeypatch.setattr(policy, "resultant_policy_name", passwords.resultant_policy_name)
    values, _ = _assess_policy(minimum_age="None")

    findings, incomplete = _run_policy(monkeypatch, values)

    assert not incomplete
    assert "Fine-grained password policy 'Strong policy' is the effective" in output.getvalue()
    assert output.getvalue().index("Fine-Grained Password Policy: Strong policy") < (
        output.getvalue().index("Fine-grained password policy 'Strong policy' is the effective")
    )
    assert "resultant policy for testing account `user`" in findings[0].commentary
    assert "minimum age: at least one day" in findings[0].commentary
    assert "lockout threshold was 0" in findings[0].commentary
    assert "not identified as applying to standard users" not in findings[0].commentary
    assert "resultant policy for testing account" in render_html(findings)
    assert [name for name, _ in calls] == [
        "password-policy-fine-grained", "password-policy-resultant",
        "password-policy-resultant-pso",
    ]
    assert all(kwargs["sensitive_values"] == ["test-secret"] for _, kwargs in calls)


def test_default_policy_presumption_is_reported_for_testing_account(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(policy, "console", Console(file=output, width=160))
    values, _ = _assess_policy(minimum_age="None")
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not incomplete
    assert "No `msDS-ResultantPSO` attribute was returned for testing account `user`" in (
        findings[0].commentary
    )
    assert "default domain password policy is used for this assessment" in (
        findings[0].commentary
    )
    assert "No msDS-ResultantPSO attribute was returned for Standard User 'user';" in (
        output.getvalue()
    )
    assert "the default domain password policy is used for this assessment." in output.getvalue()
    assert "presumed" not in output.getvalue()


def test_missing_resultant_policy_qualifies_expected_assignment(monkeypatch):
    monkeypatch.setattr(
        passwords, "run_check", lambda *_args, **_kwargs: _pso_output(
            applies_to=["CN=Domain Users,CN=Users,DC=example,DC=test"]
        ),
    )
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy(minimum_age="None")

    findings, _ = _run_policy(monkeypatch, values)

    assert "default domain password policy is used for this assessment" in (
        findings[0].commentary
    )
    assert "If a fine-grained policy is expected for this account" in findings[0].commentary


def test_failed_resultant_query_is_unknown_not_default(monkeypatch):
    def fail(*_args):
        raise CheckExecutionError("password-policy-resultant", [], stderr="LDAP query failed")

    monkeypatch.setattr(policy, "resultant_password_policy", fail)
    values, _ = _assess_policy(minimum_age="None")
    findings, incomplete = _run_policy(monkeypatch, values)
    assert any("LDAP query failed" in entry[2] for entry in incomplete)
    assert "could not be determined" in findings[0].commentary_note
    assert "default domain password policy is used for this assessment" not in findings[0].commentary


def test_unmatched_resultant_pso_is_not_assumed_to_be_default(monkeypatch):
    def fail(*_args):
        raise CheckExecutionError("password-policy-resultant-pso", [], stderr="No matching policy")

    monkeypatch.setattr(policy, "resultant_password_policy", lambda *_args: "CN=Missing,DC=example")
    monkeypatch.setattr(policy, "resultant_policy_name", fail)
    values, _ = _assess_policy(minimum_age="None")
    findings, incomplete = _run_policy(monkeypatch, values)
    assert any("No matching policy" in entry[2] for entry in incomplete)
    assert "CN=Missing,DC=example" in findings[0].commentary
    assert "settings could not be matched" in findings[0].commentary
    assert "default domain password policy is used for this assessment" not in findings[0].commentary


def test_fine_grained_policy_parser_reads_assignments_and_redacts_credentials(monkeypatch):
    calls = []

    def run(name, command, **kwargs):
        calls.append((name, command, kwargs))
        return _pso_output(applies_to=["CN=Domain Users,CN=Users,DC=example,DC=test"])

    monkeypatch.setattr(passwords, "run_check", run)
    policies, incomplete = passwords.fine_grained_password_policies("dc", "admin", "secret")
    assert incomplete is None
    assert policies[0].name == "Strong policy"
    assert policies[0].applies_to == ["CN=Domain Users,CN=Users,DC=example,DC=test"]
    assert policies[0].precedence == "1"
    assert policies[0].settings["minimum_age"] == "1 days"
    assert policies[0].settings["complexity"] == "Enabled"
    assert policies[0].settings["reversible_encryption"] == "Disabled"
    assert calls == [(
        "password-policy-fine-grained",
        ["nxc", "ldap", "dc", "-u", "admin", "-p", "secret", "--pso"],
        {"sensitive_values": ["secret"], "show_progress": False},
    )]


def test_multiple_fine_grained_policies_keep_their_own_assignments(monkeypatch):
    first = _pso_output(count=2, applies_to=["CN=Domain Users,CN=Users,DC=example,DC=test"])
    second = _pso_output(
        applies_to=["CN=Administrators,CN=Users,DC=example,DC=test"], minimum_length="8"
    ).replace("Policy Name: Strong policy", "Policy Name: Admin policy")
    second = "\n".join(second.splitlines()[1:])
    monkeypatch.setattr(passwords, "run_check", lambda *_args, **_kwargs: first + "\n" + second)

    policies, incomplete = passwords.fine_grained_password_policies("dc", "admin", "secret")

    assert incomplete is None
    assert [p.name for p in policies] == ["Strong policy", "Admin policy"]
    assert policies[0].applies_to == ["CN=Domain Users,CN=Users,DC=example,DC=test"]
    assert policies[1].applies_to == ["CN=Administrators,CN=Users,DC=example,DC=test"]
    assert policies[1].settings["minimum_length"] == "8"


def test_fine_grained_policy_table_shows_values_and_assessments(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(policy, "console", Console(file=output, width=160))
    monkeypatch.setattr(
        passwords, "run_check", lambda *_args, **_kwargs: _pso_output(minimum_age="0 days")
    )
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    policies[0].name = "25 Charater Password"
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy()
    _run_policy(monkeypatch, values)

    assert output.getvalue().rfind("└") < output.getvalue().index(
        "No msDS-ResultantPSO attribute was returned"
    )
    pso_table = output.getvalue().split("Fine-Grained Password Policy: 25 Charater Password")[1]
    rows = {line.split("│")[1].strip(): line for line in pso_table.splitlines() if "│" in line}
    for label, value, assessment in (
        ("Minimum Length", "25", "OK"),
        ("Password History", "3", "OK"),
        ("Minimum Age", "0 days", "Too Short"),
        ("Complexity", "Enabled", "OK"),
        ("Observation Window", "30 minutes", "Not applicable"),
        ("Lockout Threshold", "0", "Too Permissive"),
        ("Lockout Duration", "30 minutes", "Not applicable"),
        ("Reversible Encryption", "Disabled", "Disabled"),
        ("Applies To", "Not reported", ""),
        ("Precedence", "1", ""),
    ):
        assert value in rows[label]
        assert assessment in rows[label]
    assert "Not Set" not in rows["Minimum Age"]


def test_each_fine_grained_policy_has_a_separate_table(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(policy, "console", Console(file=output, width=160))
    first = _pso_output(count=2, applies_to=["CN=Domain Users,CN=Users,DC=example,DC=test"])
    second = _pso_output(minimum_length="8").replace(
        "Policy Name: Strong policy", "Policy Name: Admin policy"
    )
    second = "\n".join(second.splitlines()[1:])
    monkeypatch.setattr(passwords, "run_check", lambda *_args, **_kwargs: first + "\n" + second)
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    policies[1].settings["complexity"] = passwords.UNKNOWN
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy()
    _, incomplete = _run_policy(monkeypatch, values)

    first_table = output.getvalue().split("Fine-Grained Password Policy: Strong policy")[1]
    first_table, second_table = first_table.split("Fine-Grained Password Policy: Admin policy")
    assert "CN=Domain Users,CN=Users,DC=example,DC=test" in first_table
    assert "25" in first_table and "Too Short" not in first_table
    assert "Too Short" in second_table and "Unknown" in second_table
    assert any("complexity" in entry[2] for entry in incomplete)


@pytest.mark.parametrize("output", [
    "",
    _pso_output(count=2),
    _pso_output().replace("Policy Applies to:", "Unexpected assignment field:"),
    _pso_output() + "\nLDAP dc 389 DC [-] search failed",
])
def test_unverified_fine_grained_policy_enumeration_is_incomplete(monkeypatch, output):
    monkeypatch.setattr(passwords, "run_check", lambda *_args, **_kwargs: output)
    _, incomplete = passwords.fine_grained_password_policies("dc", "admin", "secret")
    assert incomplete is not None
    assert "could not be verified" in incomplete


def test_fine_grained_policy_context_and_weaknesses_are_reported(monkeypatch):
    monkeypatch.setattr(
        passwords, "run_check", lambda *_args, **_kwargs: _pso_output(
            applies_to=["CN=Domain Users,CN=Users,DC=example,DC=test"]
        )
    )
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy(minimum_age="None")

    findings, incomplete = _run_policy(monkeypatch, values)

    assert not incomplete
    finding = findings[0]
    assert "Minimum password age was zero days" in finding.commentary
    assert "CN=Domain Users,CN=Users,DC=example,DC=test" in finding.commentary
    assert "minimum age: at least one day" in finding.commentary
    assert "these settings address the corresponding default-policy weaknesses" in finding.commentary
    assert "lockout threshold was 0, disabling account lockout" in finding.commentary
    assert "effective policy for every account" in finding.commentary_note
    assert "**Note:**" in format_finding_sections(finding)["Commentary"]
    assert "<strong>Note:</strong>" in render_html([finding])
    assert "minimum password age" in finding.remediation
    assert "enabling account lockout" in finding.remediation
    assert "verify the resultant policy for affected accounts" in finding.remediation
    assert len(finding.references) == len(set(finding.references))


def test_weak_unassigned_fine_grained_policy_does_not_create_finding(monkeypatch):
    monkeypatch.setattr(
        passwords, "run_check", lambda *_args, **_kwargs: _pso_output(
            minimum_length="8"
        ).replace("Reversible Encryption: FALSE", "Reversible Encryption: TRUE")
    )
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy()
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not incomplete
    assert not findings


def test_unassigned_policy_is_not_reported_as_mitigating_default_weakness(monkeypatch):
    monkeypatch.setattr(
        passwords, "run_check",
        lambda *_args, **_kwargs: _pso_output(minimum_length="8", minimum_age="0 days"),
    )
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy(minimum_age="None")

    findings, incomplete = _run_policy(monkeypatch, values)

    assert not incomplete
    commentary = findings[0].commentary
    assert "No assigned users or groups were reported" in commentary
    assert "not identified as applying to standard users" in commentary
    assert "cannot be considered to address the identified default-policy weakness." in commentary
    paragraph = next(
        paragraph for paragraph in commentary.split("\n\n")
        if "No assigned users or groups were reported" in paragraph
    )
    assert "No `msDS-ResultantPSO` attribute was returned for testing account `user`" in paragraph
    assert "default domain password policy is used for this assessment" in paragraph
    assert "confirmed" not in paragraph
    assert "precedence" not in commentary
    assert "Verify" not in commentary
    assert "minimum age: at least one day" not in commentary
    assert "these settings address" not in commentary
    assert "The minimum password age was less than one day" not in commentary
    assert "Minimum password length was eight" not in commentary
    assert "The account lockout threshold was 0" not in commentary
    assert "enabling account lockout" not in findings[0].remediation
    assert "not identified as applying to standard users" in render_html(findings)


def test_resultant_context_is_reported_once_for_multiple_fine_grained_policies(monkeypatch):
    first = _pso_output(count=2)
    second = _pso_output().replace("Policy Name: Strong policy", "Policy Name: Other policy")
    second = "\n".join(second.splitlines()[1:])
    monkeypatch.setattr(passwords, "run_check", lambda *_args, **_kwargs: first + "\n" + second)
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy(minimum_age="None")

    findings, incomplete = _run_policy(monkeypatch, values)

    assert not incomplete
    commentary = findings[0].commentary
    assert commentary.count("No `msDS-ResultantPSO` attribute") == 1
    paragraphs = commentary.split("\n\n")
    first_policy = next(part for part in paragraphs if "fine-grained policy `Strong policy`" in part)
    second_policy = next(part for part in paragraphs if "fine-grained policy `Other policy`" in part)
    assert "testing account `user`" in first_policy
    assert "testing account `user`" not in second_policy


@pytest.mark.parametrize("subject", [
    "CN=Domain Users,CN=Users,DC=example,DC=test",
    "CN=Authenticated Users,CN=Users,DC=example,DC=test",
])
def test_assigned_policy_reports_only_mitigated_default_settings(monkeypatch, subject):
    monkeypatch.setattr(
        passwords, "run_check", lambda *_args, **_kwargs: _pso_output(applies_to=[subject])
    )
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy(minimum_age="None", lockout_threshold="0")

    findings, incomplete = _run_policy(monkeypatch, values)

    assert not incomplete
    commentary = findings[0].commentary
    assert subject in commentary
    assert "minimum age: at least one day" in commentary
    assert "For accounts for which this is the effective policy" in commentary
    assert "The policy contained the following setting" in commentary
    assert "lockout threshold was 0, disabling account lockout" in commentary
    assert "lockout threshold: " not in commentary
    assert "policy precedence" in findings[0].commentary_note


@pytest.mark.parametrize("minimum_age", ["0 days", "Unknown"])
def test_assigned_policy_does_not_claim_unverified_or_weak_settings_are_fixed(
    monkeypatch, minimum_age
):
    monkeypatch.setattr(
        passwords, "run_check",
        lambda *_args, **_kwargs: _pso_output(
            applies_to=["CN=Domain Users,CN=Users,DC=example,DC=test"], minimum_age=minimum_age
        ),
    )
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy(minimum_age="None")
    findings, incomplete = _run_policy(monkeypatch, values)

    assert "did not confirm that this policy addresses" in findings[0].commentary
    assert "these settings address" not in findings[0].commentary
    if minimum_age == "0 days":
        assert "minimum password age was less than one day" in findings[0].commentary
    else:
        assert any("minimum age" in entry[2] for entry in incomplete)


def test_not_applicable_pso_setting_does_not_mitigate_default_weakness(monkeypatch):
    monkeypatch.setattr(
        passwords, "run_check",
        lambda *_args, **_kwargs: _pso_output(
            applies_to=["CN=Domain Users,CN=Users,DC=example,DC=test"]
        ),
    )
    policies, _ = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(policy, "fine_grained_password_policies", lambda *_args: (policies, None))
    values, _ = _assess_policy(observation_window="1 minute")

    findings, _ = _run_policy(monkeypatch, values)

    assert "did not confirm that this policy addresses" in findings[0].commentary
    assert "these settings address" not in findings[0].commentary


def test_skipped_fine_grained_check_is_reported_as_incomplete(monkeypatch):
    monkeypatch.setattr(policy.typer, "confirm", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        policy, "authenticate_domain_admin", lambda: pytest.fail("unexpected administrator prompt")
    )
    values, _ = _assess_policy(minimum_age="None")
    findings, incomplete = _run_policy(monkeypatch, values)
    assert "not fully assessed" in findings[0].commentary_note
    assert "not assessed" in incomplete[0][2]


def test_failed_fine_grained_query_preserves_default_finding(monkeypatch):
    def fail(*_args):
        raise CheckExecutionError("password-policy-fine-grained", [], returncode=1)

    monkeypatch.setattr(policy, "fine_grained_password_policies", fail)
    values, _ = _assess_policy(minimum_age="None")
    findings, incomplete = _run_policy(monkeypatch, values)

    assert "Minimum password age was zero days" in findings[0].commentary
    assert "not fully assessed" in findings[0].commentary_note
    assert "password-policy-fine-grained" in incomplete[0][2]


def test_partial_fine_grained_output_reports_known_weaknesses(monkeypatch):
    monkeypatch.setattr(
        passwords, "run_check",
        lambda *_args, **_kwargs: _pso_output(
            count=2, minimum_length="8",
            applies_to=["CN=Other Group,CN=Users,DC=example,DC=test"],
        ),
    )
    policies, error = passwords.fine_grained_password_policies("dc", "admin", "secret")
    monkeypatch.setattr(
        policy, "fine_grained_password_policies", lambda *_args: (policies, error)
    )
    values, _ = _assess_policy()
    findings, incomplete = _run_policy(monkeypatch, values)

    assert "Minimum password length was eight characters" in findings[0].commentary
    assert "CN=Other Group,CN=Users,DC=example,DC=test" in findings[0].commentary
    assert "not fully assessed" in findings[0].commentary_note
    assert "could not be verified" in incomplete[0][2]


def test_fine_grained_rounded_intervals_do_not_imply_precise_values(monkeypatch):
    output = (
        _pso_output(
            minimum_age="0 days",
            applies_to=["CN=Domain Users,CN=Users,DC=example,DC=test"],
        )
        .replace("Lockout Threshold: 0", "Lockout Threshold: 5")
        .replace("Lockout Duration: 30 minutes", "Lockout Duration: 0 minutes")
        .replace("Observation Window: 30 minutes", "Observation Window: 0 minutes")
    )
    monkeypatch.setattr(passwords, "run_check", lambda *_args, **_kwargs: output)
    policies, error = passwords.fine_grained_password_policies("dc", "admin", "secret")
    assert error is None
    assert policies[0].settings["lockout_duration"] == passwords.UNKNOWN
    monkeypatch.setattr(
        policy, "fine_grained_password_policies", lambda *_args: (policies, error)
    )
    values, _ = _assess_policy()
    findings, incomplete = _run_policy(monkeypatch, values)

    assert "minimum password age was less than one day" in findings[0].commentary
    assert "lockout observation window was less than one minute" in findings[0].commentary
    assert "NetExec" not in findings[0].commentary
    assert any("lockout duration" in entry[2] for entry in incomplete)
    assert "manual unlock" not in findings[0].commentary


@pytest.mark.parametrize(("value", "word"), [("0", "passwords"), ("1", "password")])
def test_password_history_report_uses_correct_form(monkeypatch, value, word):
    values, _ = _assess_policy(password_history=value)
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not incomplete
    count_word = {"0": "0", "1": "one"}[value]
    expected = f"Password history retained {count_word} previous {word},"
    assert expected in findings[0].commentary
    assert expected in render_html(findings)


@pytest.mark.parametrize(("value", "word"), [("0", "characters"), ("1", "character")])
def test_minimum_length_report_uses_correct_form(monkeypatch, value, word):
    values, _ = _assess_policy(minimum_length=value)
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not incomplete
    count_word = {"0": "0", "1": "one"}[value]
    assert f"Minimum password length was {count_word} {word};" in findings[0].commentary


def test_multiple_weak_settings_get_only_relevant_guidance_and_deduplicated_references(monkeypatch):
    values, _ = _assess_policy(minimum_length="8", complexity="Disabled")
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not incomplete
    assert len(findings) == 1
    finding = findings[0]
    assert "Minimum password length was eight" in finding.commentary
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
    [("5", "Unknown"), ("0", "Not applicable"), ("Unknown", "Unknown")],
)
def test_netexec_not_set_lockout_duration_respects_threshold(monkeypatch, threshold, expected):
    values, assessed = _assess_policy(lockout_duration="Not Set", lockout_threshold=threshold)
    assert expected in assessed["lockout_duration"]
    _, incomplete = _run_policy(monkeypatch, values)
    if threshold in {"Unknown", "5"}:
        assert "lockout duration" in incomplete[0][2]
    else:
        assert not incomplete


def test_netexec_not_set_lockout_duration_is_verified_in_ldap(monkeypatch, tmp_path):
    output = io.StringIO()
    commands = []
    policy_output = (
        "LDAP dc 389 DC Minimum password length: 14\n"
        "LDAP dc 389 DC Password history length: 5\n"
        "LDAP dc 389 DC Minimum password age: 1 day\n"
        "LDAP dc 389 DC Domain Password Complex: 1\n"
        "LDAP dc 389 DC Reset Account Lockout Counter: 1 hour\n"
        "LDAP dc 389 DC Locked Account Duration: Not Set\n"
        "LDAP dc 389 DC Account Lockout Threshold: 5\n"
    )
    query_output = (
        "LDAP dc 389 DC [+] Response for object: DC=example,DC=test\n"
        "LDAP dc 389 DC lockoutDuration      -9223372036854775808\n"
    )

    def run(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(
            command, 0, stdout=query_output if "--query" in command else policy_output, stderr=""
        )

    monkeypatch.setattr(checks.subprocess, "run", run)
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(checks, "progress", no_progress)
    monkeypatch.setattr(policy, "progress", no_progress)
    monkeypatch.setattr(policy, "console", Console(file=output, width=200))
    monkeypatch.setattr(policy, "print_section", lambda _title: None)
    monkeypatch.setattr(policy, "require_session", lambda: {"dc_ip": "dc", "standard_user": "user"})
    monkeypatch.setattr(policy, "record_findings", lambda _items: pytest.fail("unexpected finding"))
    monkeypatch.setattr(policy, "record_incomplete", lambda *_args: pytest.fail("unexpected gap"))
    policy.run_password_policy_checks("test-secret")
    assert "Until manually unlocked" in output.getvalue()
    assert "Manual unlock" in output.getvalue()
    assert len(commands) == 2
    assert commands[1][-3:] == ["--query", "(objectClass=domainDNS)", "lockoutDuration"]
    evidence = (tmp_path / "evidence" / "password-policy-lockout-duration.txt").read_text()
    assert "-9223372036854775808" in evidence
    assert "test-secret" not in evidence


@pytest.mark.parametrize("duration,threshold", [
    ("30 minutes", "5"), ("Not Set", "0"), ("Not Set", "00"),
])
def test_unambiguous_or_disabled_lockout_skips_ldap_query(monkeypatch, duration, threshold):
    calls = []

    def run(name, _command):
        calls.append(name)
        return f"Locked Account Duration: {duration}\nAccount Lockout Threshold: {threshold}"

    monkeypatch.setattr(passwords, "run_check", run)
    parsed = passwords.password_policy_check("dc", "user", "password")
    assert parsed["lockout_duration"] == duration
    assert calls == ["password-policy"]


@pytest.mark.parametrize("query_output", [
    "LDAP dc 389 DC [-] LDAP error",
    "LDAP dc 389 DC [+] Response for object: DC=example,DC=test\n",
    "LDAP dc 389 DC [+] Response for object: DC=example,DC=test\n"
    "LDAP dc 389 DC lockoutDuration -2147483648\n",
    "LDAP dc 389 DC [+] Response for object: DC=example,DC=test\n"
    "LDAP dc 389 DC lockoutDuration -9223372036854775808\n"
    "LDAP dc 389 DC [+] Response for object: DC=other,DC=test\n"
    "LDAP dc 389 DC lockoutDuration -9223372036854775808\n",
    "command failed",
])
def test_unverified_lockout_is_unknown_and_incomplete(monkeypatch, query_output):
    def run(name, _command):
        if name == "password-policy":
            return "Locked Account Duration: Not Set\nAccount Lockout Threshold: 5"
        if query_output == "command failed":
            raise CheckExecutionError(name, [], returncode=1)
        return query_output

    monkeypatch.setattr(passwords, "run_check", run)
    parsed = passwords.password_policy_check("dc", "user", "password")
    assert parsed["lockout_duration"] == passwords.UNKNOWN
    values, _ = _assess_policy(**parsed)
    findings, incomplete = _run_policy(monkeypatch, values)
    assert not findings
    assert len(incomplete) == 1
    assert "lockout duration" in incomplete[0][2]
    assert "Lockout duration lookup:" in incomplete[0][2]
    if query_output == "command failed":
        assert "exit code 1" in incomplete[0][2]
    else:
        assert "password-policy-lockout-duration.txt" in incomplete[0][2]


def test_minimum_age_below_baseline_reports_actual_value(monkeypatch):
    values, assessed = _assess_policy(minimum_age="30 minutes")
    assert assessed["minimum_age"].startswith("[red]")
    findings, _ = _run_policy(monkeypatch, values)
    assert "Minimum password age was 30 minutes" in findings[0].commentary
    assert any("minimum-password-age" in url for url in findings[0].references)


@pytest.mark.parametrize(
    ("setting", "value", "commentary", "reference"),
    [
        ("password_history", "1", "Password history retained one", "enforce-password-history"),
        (
            "observation_window", "1 minute", "observation window was one minute",
            "reset-account-lockout-counter-after",
        ),
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
