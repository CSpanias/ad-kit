import io
from contextlib import contextmanager

import pytest
from rich.console import Console

from ad_kit.checks import ldap, nopac, smb
from ad_kit.commands import check
from ad_kit.commands.checks import privileged, unauthenticated
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.reporting import results


@contextmanager
def no_progress(_message):
    yield


def failure(name):
    return CheckExecutionError(name, [], returncode=2, stderr="command failed")


def test_smb_keeps_successes_and_reports_each_incomplete_host(monkeypatch, tmp_path):
    results.reset()
    warnings = []
    monkeypatch.setattr(results, "print_warning", warnings.append)
    monkeypatch.setattr(unauthenticated, "print_warning", warnings.append)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "tester", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["A", "B", "C"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "progress", no_progress)

    def configuration(host, _dc, *, enumerate_users):
        if host == "B":
            raise failure("smb-B")
        return {
            "host": host,
            "signing": "[red]✗ Disabled[/red]" if host == "A" else "[green]✓ Enabled[/green]",
            "smbv1": "[green]✓ Disabled[/green]", "null_auth": False,
            "anonymous_shares": None, "anonymous_users": None,
            "anonymous_incomplete": [],
        }

    def writable(host, *_args):
        if host == "A":
            return [], ["command failed"]
        return ([{"name": "share", "permissions": ("WRITE",)}] if host == "C" else []), []

    monkeypatch.setattr(unauthenticated, "smb_configuration_check", configuration)
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", writable)
    password = "test-password-not-for-report"
    unauthenticated.run_smb_checks(password)
    assert len(warnings) == 2
    assert "SMB configuration could not be fully assessed on 1 host" in warnings[0]
    assert "SMB share-access checks could not be completed on 1 host" in warnings[1]
    assert all("smb-B" not in warning and "smb-writable-A" not in warning for warning in warnings)
    results.write_reports(tmp_path)
    report = (tmp_path / "ad-kit_findings_all.html").read_text(encoding="utf-8")
    assert "SMB-001" in report and "SMB-004" in report
    assert "Incomplete checks" in report
    assert "SMB configuration - B" in report
    assert "SMB share access - A" in report
    assert password not in report
    results.reset()


def test_smb_summarises_multiple_partial_and_unknown_hosts(monkeypatch, tmp_path):
    results.reset()
    warnings = []
    monkeypatch.setattr(results, "print_warning", warnings.append)
    monkeypatch.setattr(unauthenticated, "print_warning", warnings.append)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "tester", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["A", "B", "C"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "progress", no_progress)

    def configuration(host, _dc, *, enumerate_users):
        unknown = "[yellow]⚠ Unknown[/yellow]"
        return {
            "host": host,
            "signing": unknown if host in {"A", "B"} else "[green]✓ Enabled[/green]",
            "smbv1": unknown if host == "A" else "[green]✓ Disabled[/green]",
            "null_auth": None if host == "A" else False,
            "anonymous_shares": None, "anonymous_users": None,
            "anonymous_incomplete": [],
        }

    monkeypatch.setattr(unauthenticated, "smb_configuration_check", configuration)
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: ([], []))
    unauthenticated.run_smb_checks("secret")
    assert len(warnings) == 1
    assert "2 hosts" in warnings[0]
    assert len(results._incomplete) == 2
    assert "SMB configuration - A: Unknown: signing, SMBv1, anonymous access" in results._incomplete
    assert "SMB configuration - B: Unknown: signing" in results._incomplete
    assert (tmp_path / "findings-smb-unknown-hosts.txt").read_text().splitlines() == ["A", "B"]
    results.reset()


def test_smb_configuration_warnings_precede_share_access(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    console = Console(file=output, width=160)
    monkeypatch.setattr(unauthenticated, "console", console)
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(
        unauthenticated, "print_warning", lambda message: print(message, file=output)
    )
    monkeypatch.setattr(unauthenticated, "progress", no_progress)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["A", "B"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)

    def configuration(host, _dc, *, enumerate_users):
        if host == "B":
            raise failure("smb-B")
        return {
            "host": host, "signing": "[green]✓ Enabled[/green]",
            "smbv1": "[green]✓ Disabled[/green]", "null_auth": True,
            "anonymous_shares": 1, "anonymous_users": None,
            "anonymous_incomplete": ["enumeration failed"],
        }

    def share_access(*_args):
        text = output.getvalue()
        assert text.index("SMB Checks - Hosts") < text.index("SMB configuration could not")
        assert "SMB anonymous enumeration could not" in text
        assert "SMB Checks - Share Access" not in text
        return [], ["share-access failed"]

    monkeypatch.setattr(unauthenticated, "smb_configuration_check", configuration)
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", share_access)
    unauthenticated.run_smb_checks("secret")
    text = output.getvalue()
    assert text.index("SMB Checks - Share Access") < text.index(
        "SMB share-access checks could not"
    )
    results.reset()


def test_smb_omits_hosts_without_usable_results_but_retains_coverage(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    share_hosts = []
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "tester", "domain_computers_exported": True,
    })
    hosts = ["OFFLINE", "DC-FAIL", "FILTERED", "PARTIAL", "AVAILABLE"]
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: hosts)
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: ["DC-FAIL"])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "progress", no_progress)
    monkeypatch.setattr(unauthenticated, "track_items", lambda items, _label: items)
    monkeypatch.setattr(
        unauthenticated, "smb_share_access_check",
        lambda host, *_args: (share_hosts.append(host) or [], []),
    )

    def run(name, _command, **_kwargs):
        if name == "smb-DC-FAIL":
            raise failure(name)
        if name == "smb-FILTERED":
            return "SMB FILTERED 445 FILTERED [-] Connection failed"
        if name == "smb-PARTIAL":
            return "SMB PARTIAL 445 PARTIAL (signing:False)"
        if name == "smb-AVAILABLE":
            return (
                "SMB AVAILABLE 445 AVAILABLE (signing:True) (SMBv1:False)\n"
                "SMB AVAILABLE 445 AVAILABLE [-] EXAMPLE\\: STATUS_LOGON_FAILURE"
            )
        return ""

    monkeypatch.setattr(smb, "run_check", run)
    unauthenticated.run_smb_checks("secret")
    tables = output.getvalue().split("SMB Checks - Share Access")[0]
    assert all(host not in tables for host in ("OFFLINE", "DC-FAIL", "FILTERED"))
    assert "PARTIAL" not in tables and "AVAILABLE" not in tables
    assert "SMB Signing" in tables and "Unknown" in tables
    assert sorted(share_hosts) == sorted(hosts)
    for host in ("OFFLINE", "DC-FAIL", "FILTERED", "PARTIAL"):
        assert any(f"SMB configuration - {host}:" in entry for entry in results._incomplete)
    assert (tmp_path / "findings-smb-unknown-hosts.txt").read_text().splitlines() == [
        "DC-FAIL", "FILTERED", "OFFLINE", "PARTIAL",
    ]
    assert any(finding.id == "SMB-001" for finding in results._findings)
    results.reset()


def test_failed_anonymous_enumeration_keeps_smb_configuration(monkeypatch):
    results.reset()
    warnings = []
    monkeypatch.setattr(results, "print_warning", warnings.append)
    def run(name, _command, **_kwargs):
        if name.startswith("smb-anonymous"):
            raise failure(name)
        return (
            "SMB dc 445 HOST (signing:False) (SMBv1:False)\n"
            "SMB dc 445 HOST [+] EXAMPLE\\:"
        )

    monkeypatch.setattr(smb, "run_check", run)
    result = smb.smb_configuration_check("host", "dc")
    assert result["signing"] == "[red]✗ Disabled[/red]"
    assert result["anonymous_shares"] is None
    assert "smb-anonymous-enumeration-host" in result["anonymous_incomplete"][0]
    assert not warnings
    results.reset()


def test_smb_summarises_anonymous_enumeration_failures(monkeypatch, tmp_path):
    results.reset()
    warnings = []
    monkeypatch.setattr(results, "print_warning", warnings.append)
    monkeypatch.setattr(unauthenticated, "print_warning", warnings.append)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "tester", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["A", "B"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "progress", no_progress)
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: ([], []))

    def run(name, _command, **_kwargs):
        if name.startswith("smb-anonymous"):
            raise failure(name)
        return (
            "SMB dc 445 HOST (signing:True) (SMBv1:False)\n"
            "SMB dc 445 HOST [+] EXAMPLE\\:"
        )

    monkeypatch.setattr(smb, "run_check", run)
    unauthenticated.run_smb_checks("secret")
    assert len(warnings) == 1
    assert "SMB anonymous enumeration could not be completed on 2 hosts" in warnings[0]
    assert len(results._incomplete) == 2
    assert "SMB anonymous enumeration - A" in results._incomplete[0]
    assert "SMB anonymous enumeration - B" in results._incomplete[1]
    results.reset()


def test_ldap_and_nopac_continue_after_failed_controller(monkeypatch):
    results.reset()
    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: ["DC1.EXAMPLE", "DC2.EXAMPLE"])

    def ldap_run(name, _command, **_kwargs):
        if name.endswith("DC2.EXAMPLE"):
            raise failure(name)
        return (
            "LDAP (signing:None) (channel binding:Always)\n"
            "LDAP successful bind must be completed"
        )

    monkeypatch.setattr(ldap, "run_check", ldap_run)
    ldap_results, ldap_findings = ldap.ldap_check()
    assert ldap_findings[0].affected_assets == ["DC1.EXAMPLE"]
    assert ldap_results[1]["signing"] == "[yellow]⚠ Unknown[/yellow]"

    def nopac_run(name, _command, sensitive_values, *, kerberos_dc):
        if name.endswith("2"):
            raise failure(name)
        return "TGT with PAC size 1800\nTGT without PAC size 1700\nVULNERABLE"

    monkeypatch.setattr(nopac, "run_check", nopac_run)
    nopac_results, nopac_findings = nopac.nopac_check(["192.0.2.1", "192.0.2.2"], "user", "secret")
    assert nopac_findings[0].affected_assets == ["192.0.2.1"]
    assert nopac_results[1]["status"] == "Unable to assess"
    assert len(results._incomplete) == 3
    results.reset()


def test_asrep_finding_survives_privileged_lookup_failure(monkeypatch, tmp_path):
    results.reset()
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
        "domain_users_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "progress", no_progress)
    finding = Finding("ASREP-001", "AS-REP", "Comment", "Fix")
    monkeypatch.setattr(unauthenticated, "asreproast_check", lambda *_args: (
        {"account_count": 1, "accounts": ["user"]}, [finding]
    ))

    def failed_lookup(*_args):
        raise failure("privileged-lookup")

    monkeypatch.setattr(unauthenticated, "asreproast_privileged_check", failed_lookup)
    unauthenticated.run_asreproast_checks("secret")
    results.write_reports(tmp_path)
    report = (tmp_path / "ad-kit_findings_all.html").read_text(encoding="utf-8")
    assert "ASREP-001" in report
    assert "AS-REP privileged membership" in report
    results.reset()


def test_privileged_finding_survives_later_subcheck_failure(monkeypatch, tmp_path):
    results.reset()
    monkeypatch.setattr(privileged, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain": "example.test",
    })
    monkeypatch.setattr(privileged, "progress", no_progress)
    finding = Finding("PRIV-001", "Privileged", "Comment", "Fix")
    monkeypatch.setattr(
        privileged, "privileged_excessive_check", lambda *_args: ({}, [finding])
    )

    def failed_builtin(*_args):
        raise failure("built-in")

    monkeypatch.setattr(privileged, "builtin_accounts_check", failed_builtin)
    with pytest.raises(CheckExecutionError):
        privileged.run_privileged_group_checks("secret")
    results.write_reports(tmp_path)
    assert "PRIV-001" in (tmp_path / "ad-kit_findings_all.html").read_text(encoding="utf-8")
    results.reset()


def test_privileged_tables_are_separated(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda _title: None)
    monkeypatch.setattr(privileged, "progress", no_progress)
    monkeypatch.setattr(privileged, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain": "example.test",
    })
    monkeypatch.setattr(privileged, "privileged_excessive_check", lambda *_args: ({
        "groups": {
            "Domain Admins": {"members": [], "member_count": 0, "percentage": 0},
            "Enterprise Admins": {"members": [], "member_count": 0, "percentage": 0},
        },
        "admin_count": {"member_count": 0, "percentage": 0},
    }, []))
    monkeypatch.setattr(privileged, "builtin_accounts_check", lambda *_args: ({
        "administrator": {"enabled": False, "account_name": "Administrator"},
        "guest": {"enabled": False, "account_name": "Guest"},
    }, []))
    monkeypatch.setattr(privileged, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(privileged, "dcsync_check", lambda *_args: [])
    monkeypatch.setattr(privileged, "record_findings", lambda _findings: None)

    privileged.run_privileged_group_checks("secret")

    text = output.getvalue()
    assert text.count("┘\n\n") == 2
    assert "Built-in Account Status" in text
    assert "Unexpected DCSync Principals" in text


def test_skipped_module_is_listed_in_report(monkeypatch, tmp_path):
    finding = Finding("SMB-001", "SMB", "Comment", "Fix")
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setitem(check.AVAILABLE_CHECKS, "successful-test", check.CheckDefinition(
        lambda password: (results.record_findings([finding]), password)[1], False
    ))

    def failed(_password):
        raise failure("failed-module")

    monkeypatch.setitem(
        check.AVAILABLE_CHECKS, "failed-test", check.CheckDefinition(failed, False)
    )
    check.run_selected_checks(["successful-test", "failed-test"])
    report = (tmp_path / "ad-kit_findings_successful-test_failed-test.html").read_text(
        encoding="utf-8"
    )
    assert "SMB-001" in report
    assert "Incomplete checks" in report and "failed-test" in report
    results.reset()
