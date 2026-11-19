from contextlib import contextmanager

import pytest

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
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "tester", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["A", "B", "C"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "progress", no_progress)

    def configuration(host, _dc):
        if host == "B":
            raise failure("smb-B")
        return {
            "host": host, "signing": "[red]✗ Disabled[/red]" if host == "A" else "[green]✓ Enabled[/green]",
            "smbv1": "[green]✓ Disabled[/green]", "null_auth": False,
            "anonymous_shares": None, "anonymous_users": None,
        }

    def writable(host, *_args):
        if host == "A":
            raise failure("smb-writable-A")
        return ["share WRITE"] if host == "C" else []

    monkeypatch.setattr(unauthenticated, "smb_configuration_check", configuration)
    monkeypatch.setattr(unauthenticated, "smb_writable_share_check", writable)
    unauthenticated.run_smb_checks("secret")
    results.write_reports(tmp_path)
    report = (tmp_path / "ad-kit_findings.html").read_text(encoding="utf-8")
    assert "SMB-001" in report and "SMB-004" in report
    assert "Incomplete checks" in report
    assert "SMB configuration - B" in report
    assert "SMB writable shares - A" in report
    assert "secret" not in report
    results.reset()


def test_failed_anonymous_enumeration_keeps_smb_configuration(monkeypatch):
    results.reset()
    def run(name, _command):
        if name.startswith("smb-anonymous"):
            raise failure(name)
        return "SMB dc 445 HOST (signing:False) (SMBv1:False) (null auth:True)"

    monkeypatch.setattr(smb, "run_check", run)
    result = smb.smb_configuration_check("host", "dc")
    assert result["signing"] == "[red]✗ Disabled[/red]"
    assert result["anonymous_shares"] is None
    assert "SMB anonymous enumeration - host" in results._incomplete[0]
    results.reset()


def test_ldap_and_nopac_continue_after_failed_controller(monkeypatch):
    results.reset()
    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: ["DC1.EXAMPLE", "DC2.EXAMPLE"])

    def ldap_run(name, _command):
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

    def nopac_run(name, _command, sensitive_values):
        if name.endswith("2"):
            raise failure(name)
        return "TGT with PAC size 1800\nTGT without PAC size 1700\nVULNERABLE"

    monkeypatch.setattr(nopac, "run_check", nopac_run)
    nopac_results, nopac_findings = nopac.nopac_check(["192.0.2.1", "192.0.2.2"], "user", "secret")
    assert nopac_findings[0].affected_assets == ["192.0.2.1"]
    assert nopac_results[1]["status"] == "Unable to assess"
    assert len(results._incomplete) == 2
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
    report = (tmp_path / "ad-kit_findings.html").read_text(encoding="utf-8")
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
    assert "PRIV-001" in (tmp_path / "ad-kit_findings.html").read_text(encoding="utf-8")
    results.reset()


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
    report = (tmp_path / "ad-kit_findings.html").read_text(encoding="utf-8")
    assert "SMB-001" in report
    assert "Incomplete checks" in report and "failed-test" in report
    results.reset()
