import io
from contextlib import nullcontext

import pytest
from rich.console import Console

from ad_kit.commands import check
from ad_kit.commands.checks import credentials
from ad_kit.core import console as console_helpers


@pytest.fixture(autouse=True)
def isolate_reports(monkeypatch, tmp_path):
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)


@pytest.mark.parametrize("admin", [False, True])
def test_authentication_success_is_followed_by_blank_line(monkeypatch, admin):
    output = io.StringIO()
    prompts = []
    console = Console(file=output)
    monkeypatch.setattr(credentials, "console", console)
    monkeypatch.setattr(credentials, "print_success", lambda message: console.print(message))
    monkeypatch.setattr(credentials, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user",
    })
    monkeypatch.setattr(credentials, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(credentials, "validate_credentials", lambda *_args: "valid")
    monkeypatch.setattr(
        credentials.typer, "prompt", lambda label, **_kwargs: prompts.append(label) or "test"
    )

    if admin:
        credentials.authenticate_domain_admin()
    else:
        credentials.authenticate_standard_user()
        assert prompts == ["Enter the Standard User password"]
    assert output.getvalue().endswith("Authentication succeeded.\n\n")


@pytest.mark.parametrize(("module", "runner", "heading"), [
    ("pass-pol", "run_password_policy_checks", "Password Policy"),
    ("dns", "run_dns_checks", "DNS Record Creation"),
    ("maq", "run_maq_checks", "Machine Account Quota"),
    ("tombstone", "run_tombstone_checks", "Deleted AD Object Access"),
    ("password-not-required", "run_password_not_required_checks", "Password Not Required Accounts"),
    ("password-never-expires", "run_password_never_expires_checks", "Password Never Expires Accounts"),
    ("pre2k", "run_pre2k_checks", "Pre-Windows 2000 Computer Accounts"),
    ("nopac", "run_nopac_checks", "NoPAC Check"),
    ("scriptPath", "run_scriptpath_checks", "User Logon Script Paths"),
    ("privileged", "run_privileged_group_checks", "Privileged Group Membership"),
    ("delegation", "run_delegation_checks", "Delegation"),
    ("kerberoast", "run_kerberoast_checks", "Kerberoasting"),
    ("adcs", "run_adcs_checks", "Active Directory Certificate Services"),
    ("local-admin", "run_local_admin_checks", "Local Administrator Access"),
    ("ldap-info", "run_ldap_info_checks", "LDAP Information Exposure"),
    ("coercion", "run_coercion_checks", "Authentication Coercion"),
])
def test_check_heading_has_one_blank_line_after_authentication(
    monkeypatch, module, runner, heading
):
    output = io.StringIO()
    console = Console(file=output)
    monkeypatch.setattr(credentials, "console", console)
    monkeypatch.setattr(console_helpers, "console", console)
    monkeypatch.setattr(credentials, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user",
    })
    monkeypatch.setattr(credentials, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(credentials, "validate_credentials", lambda *_args: "valid")
    monkeypatch.setattr(credentials.typer, "prompt", lambda *_args, **_kwargs: "test")
    monkeypatch.setattr(
        check, runner, lambda _password: console_helpers.print_section(heading),
    )

    check.run_selected_checks([module])

    assert f"Authentication succeeded.\n\n[{heading}]\n" in output.getvalue()
    assert f"Authentication succeeded.\n\n\n[{heading}]" not in output.getvalue()


def test_full_workflow_heading_has_one_blank_line_after_authentication(monkeypatch):
    output = io.StringIO()
    console = Console(file=output)
    monkeypatch.setattr(credentials, "console", console)
    monkeypatch.setattr(console_helpers, "console", console)
    monkeypatch.setattr(credentials, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user",
    })
    monkeypatch.setattr(credentials, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(credentials, "validate_credentials", lambda *_args: "valid")
    monkeypatch.setattr(credentials.typer, "prompt", lambda *_args, **_kwargs: "test")
    monkeypatch.setattr(
        check, "run_dns_checks", lambda _password: console_helpers.print_section("DNS Record Creation")
    )

    check.run_checks(exclude=set(check.AVAILABLE_CHECKS) - {"dns"})

    assert "Authentication succeeded.\n\n[DNS Record Creation]\n" in output.getvalue()
    assert "Authentication succeeded.\n\n\n[DNS Record Creation]" not in output.getvalue()


def test_check_all_reuses_smb_password_for_asreproast(monkeypatch):
    asreproast_passwords = []

    monkeypatch.setattr(check, "run_ldap_checks", lambda: None)
    monkeypatch.setattr(
        check,
        "run_smb_checks",
        lambda std_pass=None: "smb-password",
    )

    def fake_asreproast(std_pass=None):
        asreproast_passwords.append(std_pass)
        return std_pass

    monkeypatch.setattr(check, "run_asreproast_checks", fake_asreproast)

    authenticated_checks = (
        "run_local_admin_checks",
        "run_password_policy_checks",
        "run_password_not_required_checks",
        "run_password_never_expires_checks",
        "run_maq_checks",
        "run_dns_checks",
        "run_pre2k_checks",
        "run_nopac_checks",
        "run_scriptpath_checks",
        "run_privileged_group_checks",
        "run_delegation_checks",
        "run_kerberoast_checks",
        "run_adcs_checks",
        "run_ldap_info_checks",
        "run_tombstone_checks",
        "run_coercion_checks",
    )
    for name in authenticated_checks:
        monkeypatch.setattr(check, name, lambda *_args: None)

    check.run_checks()

    assert asreproast_passwords == ["smb-password"]


def test_selected_smb_and_asreproast_reuse_password(monkeypatch):
    asreproast_passwords = []

    monkeypatch.setattr(
        check,
        "run_smb_checks",
        lambda std_pass=None: "smb-password",
    )

    def fake_asreproast(std_pass=None):
        asreproast_passwords.append(std_pass)
        return std_pass

    monkeypatch.setattr(check, "run_asreproast_checks", fake_asreproast)

    check.run_selected_checks(["smb", "asreproast"])

    assert asreproast_passwords == ["smb-password"]


def test_check_all_does_not_add_extra_blank_line_prints(monkeypatch):
    printed = []

    monkeypatch.setattr(
        check.console,
        "print",
        lambda *args, **kwargs: printed.append(args),
    )
    monkeypatch.setattr(check, "run_ldap_checks", lambda: None)
    monkeypatch.setattr(
        check,
        "run_smb_checks",
        lambda std_pass=None: "smb-password",
    )
    monkeypatch.setattr(
        check,
        "run_asreproast_checks",
        lambda std_pass=None: std_pass,
    )

    authenticated_checks = (
        "run_local_admin_checks",
        "run_password_policy_checks",
        "run_password_not_required_checks",
        "run_password_never_expires_checks",
        "run_maq_checks",
        "run_dns_checks",
        "run_pre2k_checks",
        "run_nopac_checks",
        "run_scriptpath_checks",
        "run_privileged_group_checks",
        "run_delegation_checks",
        "run_kerberoast_checks",
        "run_adcs_checks",
        "run_ldap_info_checks",
        "run_tombstone_checks",
        "run_coercion_checks",
    )
    for name in authenticated_checks:
        monkeypatch.setattr(check, name, lambda *_args: None)

    check.run_checks()

    assert printed == []


def test_selected_checks_does_not_add_extra_blank_line_prints(monkeypatch):
    printed = []

    monkeypatch.setattr(
        check.console,
        "print",
        lambda *args, **kwargs: printed.append(args),
    )
    monkeypatch.setattr(check, "run_ldap_checks", lambda: None)
    monkeypatch.setattr(
        check,
        "run_smb_checks",
        lambda std_pass=None: None,
    )

    check.run_selected_checks(["ldap", "smb"])

    assert printed == []


def test_check_all_exclusions_preserve_order_and_authentication(monkeypatch):
    calls = []
    exclude = set(check.AVAILABLE_CHECKS) - {"ldap", "asreproast", "maq", "dns"}
    exclude.add("dns")

    monkeypatch.setattr(check, "run_ldap_checks", lambda: calls.append(("ldap", None)))
    monkeypatch.setattr(
        check, "run_asreproast_checks",
        lambda password: calls.append(("asreproast", password)),
    )
    monkeypatch.setattr(check, "run_maq_checks", lambda password: calls.append(("maq", password)))
    monkeypatch.setattr(
        check, "run_dns_checks", lambda _password: pytest.fail("excluded DNS check ran")
    )
    monkeypatch.setattr(
        check, "authenticate_standard_user",
        lambda **_kwargs: calls.append(("auth", None)) or "secret"
    )
    monkeypatch.setattr(check.results, "write_reports", lambda *_args, **_kwargs: None)

    check.run_checks(exclude=exclude)
    assert calls == [
        ("ldap", None), ("asreproast", None), ("auth", None), ("maq", "secret"),
    ]


def test_check_all_with_only_unauthenticated_check_skips_password_prompt(monkeypatch):
    calls = []
    monkeypatch.setattr(check, "run_ldap_checks", lambda: calls.append("ldap"))
    monkeypatch.setattr(
        check, "authenticate_standard_user", lambda: pytest.fail("unexpected password prompt")
    )
    monkeypatch.setattr(check.results, "write_reports", lambda *_args, **_kwargs: None)
    check.run_checks(exclude=set(check.AVAILABLE_CHECKS) - {"ldap"})
    assert calls == ["ldap"]
