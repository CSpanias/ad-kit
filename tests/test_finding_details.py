import io
from contextlib import contextmanager, nullcontext

import pytest
from rich.console import Console

from ad_kit.checks import kerberoast
from ad_kit.checks.ldap_info import is_sensitive_value
from ad_kit.commands.checks import policy, privileged, unauthenticated
from ad_kit.core.checks import CheckEvidence
from ad_kit.core.exceptions import CheckExecutionError


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("SQL Server Service Account", False),
        ("Secretarial Support", False),
        ("For VPN Test to be deleted after", False),
        ("Testing SQL", False),
        ("General SQL", False),
        ("Partner SQL Archive", False),
        ("Partner SQL", False),
        ("PASSWORD: example", True),
        ("secret: example", True),
        ("API key: example", True),
        ("Credentials stored here", True),
        ("passwordless account", False),
    ],
)
def test_ldap_keyword_matching_avoids_generic_services_and_partial_words(value, expected):
    assert is_sensitive_value(value) is expected


def test_kerberoast_parses_names_not_spns_and_ignores_other_output(monkeypatch, tmp_path):
    def row(spn, account, member):
        return f"{spn:<32}  {account:<16}  {member:<12}  <never>          <never>"

    output = "\n".join([
        "Impacket v0.13",
        row("ServicePrincipalName", "Name", "MemberOf").replace(
            "<never>", "PasswordLastSet", 1
        ),
        "-" * 32 + "  " + "-" * 16 + "  " + "-" * 12,
        row("MSSQLSvc/sql.example.test:1433", "SQL Service", ""),
        row("HTTP/web.example.test", "SQL Service", ""),
        row("HTTP/other.example.test", "websvc", ""),
        "",
        "[-] Principal: EXAMPLE\\websvc - ticket request failed",
    ])
    monkeypatch.setattr(kerberoast, "run_check", lambda *_args: output)
    monkeypatch.setattr(kerberoast, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(kerberoast, "get_privileged_users", lambda *_args: {"websvc"})

    result, findings = kerberoast.kerberoast_check("dc", "example.test", "user", "pw")
    assert result["accounts"] == ["SQL Service", "websvc"]
    assert result["account_count"] == 2
    assert [finding.id for finding in findings] == ["KERB-001", "KERB-002"]
    assert all("successfully requested" not in entry for f in findings for entry in f.evidence)


def test_kerberoast_rejects_unrecognised_output(monkeypatch, tmp_path):
    monkeypatch.setattr(kerberoast, "run_check", lambda *_args: "Unexpected output")
    monkeypatch.setattr(kerberoast, "get_artefacts_dir", lambda: tmp_path)
    with pytest.raises(CheckExecutionError, match="Could not parse"):
        kerberoast.kerberoast_check("dc", "example.test", "user", "pw")


def test_kerberoast_empty_result_is_not_a_parse_error(monkeypatch, tmp_path):
    monkeypatch.setattr(kerberoast, "run_check", lambda *_args: "No entries found!")
    monkeypatch.setattr(kerberoast, "get_artefacts_dir", lambda: tmp_path)
    result, findings = kerberoast.kerberoast_check("dc", "example.test", "user", "pw")
    assert result["accounts"] == [] and findings == []


@pytest.mark.parametrize("kind", ["delegation", "kerberoast", "asreproast"])
def test_affected_accounts_are_shown_in_correct_rows(monkeypatch, kind):
    output = io.StringIO()
    module = unauthenticated if kind == "asreproast" else privileged
    monkeypatch.setattr(module, "console", Console(file=output, width=160))
    monkeypatch.setattr(module, "print_section", lambda *_args: None)
    monkeypatch.setattr(module, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(module, "record_findings", lambda *_args: None)
    monkeypatch.setattr(module, "require_session", lambda: {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
        "domain_users_exported": True,
    })
    if kind == "delegation":
        monkeypatch.setattr(module, "delegation_check", lambda *_args: (
            {"unconstrained": ["service[red]"], "protocol_transition": []}, []
        ))
        module.run_delegation_checks("pw")
        assert "service[red]" in output.getvalue()
        assert "Protocol Transition" in output.getvalue()
    elif kind == "kerberoast":
        monkeypatch.setattr(module, "kerberoast_check", lambda *_args: (
            {"account_count": 1, "accounts": ["svc"]}, []
        ))
        module.run_kerberoast_checks("pw")
        assert "svc" in output.getvalue()
    else:
        monkeypatch.setattr(module, "require_collected_data", lambda *_args: None)
        monkeypatch.setattr(module, "asreproast_check", lambda *_args: (
            {"account_count": 2, "accounts": ["alice", "admin"]}, []
        ))
        monkeypatch.setattr(module, "asreproast_privileged_check", lambda *_args: (["admin"], []))
        module.run_asreproast_checks("pw")
        text = output.getvalue()
        assert "alice" in text
        assert text.count("admin") == 2


def test_ldap_info_displays_accounts_without_sensitive_values(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda *_args: None)
    monkeypatch.setattr(privileged, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(privileged, "record_findings", lambda *_args: None)
    monkeypatch.setattr(privileged, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user",
    })
    monkeypatch.setattr(privileged, "ldap_info_check", lambda *_args: {
        "descriptions": [
            {"user": "alice", "value": "password: hidden"},
            {"user": "bob", "value": "SQL Server Service Account"},
        ],
        "info_fields": [],
        "user_passwords": ["User: charlie userPassword: hidden-hash"],
        "unix_passwords": [],
    })
    privileged.run_ldap_info_checks("pw")
    text = output.getvalue()
    assert "alice" in text and "charlie" in text
    assert "description" in text and "userPassword" in text
    assert "bob" not in text and "hidden" not in text


@pytest.mark.parametrize("has_finding", [True, False])
def test_coercion_shows_only_matching_redacted_example(monkeypatch, has_finding):
    output = io.StringIO()
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(privileged, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(privileged, "record_findings", lambda *_args: None)
    monkeypatch.setattr(privileged, "require_session", lambda: {"standard_user": "user"})
    monkeypatch.setattr(privileged, "coercion_check", lambda *_args: {
        "coercion_dcs": {"DC1": ["PetitPotam"]} if has_finding else {},
        "spooler_dcs": [],
    })

    @contextmanager
    def evidence():
        yield [CheckEvidence(
            "coercion-plus", ["nxc", "-p", "***"],
            "SMB 192.0.2.2 445 DC2 VULNERABLE, other\n"
            "SMB 192.0.2.1 445 DC1 VULNERABLE, PetitPotam",
            "",
        )]

    monkeypatch.setattr(privileged, "capture_check_evidence", evidence)
    privileged.run_coercion_checks("password")
    text = output.getvalue()
    assert ("Command Evidence" in text) is has_finding
    assert ("VULNERABLE, PetitPotam" in text) is has_finding
    assert "DC2 VULNERABLE" not in text
    assert "password" not in text


def test_coercion_methods_are_shown_for_each_host(monkeypatch):
    output = io.StringIO()
    recorded_findings = []
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda *_args: None)
    monkeypatch.setattr(privileged, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(privileged, "record_findings", recorded_findings.extend)
    monkeypatch.setattr(privileged, "require_session", lambda: {"standard_user": "user"})
    monkeypatch.setattr(privileged, "coercion_check", lambda *_args: {
        "coercion_dcs": {"DC1": ["PetitPotam", "WebDAV"], "DC2": ["DFSCoerce"]},
        "spooler_dcs": ["DC3"],
    })

    privileged.run_coercion_checks("pw")

    lines = output.getvalue().splitlines()
    assert any("DC1" in line and "PetitPotam, WebDAV" in line for line in lines)
    assert any("DC2" in line and "DFSCoerce" in line for line in lines)
    assert "DCs with Print Spooler" not in output.getvalue()
    assert any("Print Spooler" in evidence and "DC3" in evidence
               for finding in recorded_findings for evidence in finding.evidence)


@pytest.mark.parametrize("kind", ["local_admin", "adcs", "pre2k", "tombstone"])
def test_other_checks_show_known_affected_objects(monkeypatch, kind):
    module = (
        privileged if kind == "adcs"
        else unauthenticated if kind == "tombstone"
        else policy
    )
    output = io.StringIO()
    monkeypatch.setattr(module, "console", Console(file=output, width=160))
    monkeypatch.setattr(module, "print_section", lambda *_args: None)
    monkeypatch.setattr(module, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(module, "record_findings", lambda *_args: None)
    monkeypatch.setattr(module, "require_session", lambda: {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
        "domain_computers_exported": True,
    })
    if kind == "local_admin":
        monkeypatch.setattr(module, "require_collected_data", lambda *_args: None)
        monkeypatch.setattr(module, "local_admin_check", lambda *_args: {
            "hosts": ["WS01"], "domain_controllers": [],
        })
        module.run_local_admin_checks("pw")
        expected = "WS01"
    elif kind == "adcs":
        monkeypatch.setattr(module, "adcs_check", lambda *_args: ({"ESC1": ["Template1"]}, []))
        monkeypatch.setattr(module, "print_info", lambda *_args: None)
        module.run_adcs_checks("pw")
        expected = "Template1"
    elif kind == "pre2k":
        monkeypatch.setattr(module, "pre2k_check", lambda *_args: (
            {"accounts_found": 1, "accounts": ["OLDPC$"], "tgt_obtained": True},
            [object()],
        ))
        module.run_pre2k_checks("pw")
        expected = "OLDPC$"
    else:
        monkeypatch.setattr(module, "track_items", lambda items, _label: items)
        monkeypatch.setattr(module, "tombstone_check", lambda *_args: {
            "dc_hostname": "DC1", "deleted_objects": 1,
            "sam_account_names": ["deleted-user"], "status": "Enumerated",
        })
        module.run_tombstone_checks("pw")
        expected = "deleted-user"
    assert expected in output.getvalue()


def test_privileged_summary_omits_member_list(monkeypatch):
    output = io.StringIO()
    findings = [object()]
    recorded_findings = []
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda *_args: None)
    monkeypatch.setattr(privileged, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(privileged, "record_findings", recorded_findings.append)
    monkeypatch.setattr(privileged, "require_session", lambda: {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
    })
    monkeypatch.setattr(privileged, "privileged_excessive_check", lambda *_args: ({
        "groups": {
            "Domain Admins": {"member_count": 1, "percentage": 10.0, "members": ["alice"]},
            "Enterprise Admins": {"member_count": 1, "percentage": 1.0, "members": ["bob"]},
        },
        "admin_count": {"member_count": 1, "percentage": 25.0, "members": ["stale"]},
    }, findings))
    monkeypatch.setattr(privileged, "builtin_accounts_check", lambda *_args: ({
        "administrator": {"enabled": False, "account_name": "administrator"},
        "guest": {"enabled": False, "account_name": "guest"},
    }, []))
    monkeypatch.setattr(privileged, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(privileged, "dcsync_check", lambda *_args: [])
    privileged.run_privileged_group_checks("pw")
    text = output.getvalue()
    assert "Domain Admins" in text and "adminCount=1 accounts" in text
    assert "Excessive" in text and "Review" in text
    assert "Accounts Requiring Review" not in text
    assert all(member not in text for member in ("alice", "bob", "stale"))
    assert findings in recorded_findings
