import io
from contextlib import contextmanager, nullcontext

import pytest
from rich.console import Console

from ad_kit.checks import (
    asreproast,
    delegations,
    kerberoast,
    password_never_expires,
    password_not_required,
    pre2k,
)
from ad_kit.checks.ldap_info import is_sensitive_value
from ad_kit.commands.checks import policy, privileged, unauthenticated
from ad_kit.core.checks import CheckEvidence
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import format_counted_commentary
from ad_kit.reporting.html import render_html
from ad_kit.reporting.markdown import format_finding_sections


@pytest.mark.parametrize(("count", "expected"), [
    (0, "0"), (1, "one"), (2, "two"), (3, "three"), (4, "four"),
    (5, "five"), (6, "six"), (7, "seven"), (8, "eight"), (9, "nine"), (10, "10"),
])
def test_finding_commentary_spells_out_small_counts(count, expected):
    finding = Finding("TEST-001", "Example", "Found {count} {subject}.", "")
    format_counted_commentary(finding, count, "system", "systems")
    subject = "system" if count == 1 else "systems"
    assert finding.commentary == f"Found {expected} {subject}."


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
    assert "identified\ntwo accounts associated" in findings[0].commentary
    assert "identified one\nprivileged account associated" in findings[1].commentary
    assert "two Kerberoastable accounts were identified." in findings[0].evidence[-1]
    assert "one privileged Kerberoastable account was identified." in findings[1].evidence[-1]
    for finding in findings:
        assert "Service Principal Names (SPNs)" in finding.commentary
        assert all("Service Principal Name" not in entry for entry in finding.evidence)
        assert any("SPN" in entry for entry in finding.evidence)
        assert "Service Principal Names (SPNs)" in finding.remediation
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


@pytest.mark.parametrize(("count", "phrase"), [(1, "account was"), (2, "accounts were")])
def test_asreproast_finding_counts_use_correct_grammar(monkeypatch, tmp_path, count, phrase):
    accounts = [f"user{i}" for i in range(count)]
    (tmp_path / "domain-users-filtered.txt").write_text("\n".join(accounts), encoding="utf-8")
    (tmp_path / "asreproastable-users.txt").write_text(
        "\n".join(f"$krb5asrep$23${account}@example.test:hash" for account in accounts),
        encoding="utf-8",
    )
    monkeypatch.setattr(asreproast, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(asreproast, "run_check", lambda *_args: "")
    monkeypatch.setattr(asreproast, "get_privileged_users", lambda *_args: set(accounts))
    result, findings = asreproast.asreproast_check("dc", "example.test")
    _, privileged_findings = asreproast.asreproast_privileged_check(
        "dc", result["accounts"], "user", "pw"
    )
    count_word = {1: "one", 2: "two"}[count]
    assert f"{count_word} AS-REP roastable {phrase} identified." in findings[0].evidence[-1]
    assert f"{count_word} privileged AS-REP roastable {phrase} identified." in (
        privileged_findings[0].evidence[-1]
    )
    assert f"A total of {count_word} {phrase.split()[0]} configured" in (
        privileged_findings[0].commentary
    )


@pytest.mark.parametrize("module", [password_not_required, password_never_expires])
@pytest.mark.parametrize(("count", "noun", "count_word"), [
    (1, "account", "one"), (2, "accounts", "two"),
])
def test_password_account_commentary_uses_actual_count(
    monkeypatch, module, count, noun, count_word
):
    output = "\n".join(
        f"LDAP dc 389 DC User: user{i} Status: enabled" for i in range(count)
    )
    monkeypatch.setattr(module, "run_check", lambda *_args: output)
    check = (
        module.password_not_required_check
        if module is password_not_required else module.password_never_expires_check
    )
    _, findings = check("dc", "user", "password")
    assert f"identified {count_word} {noun} with the" in findings[0].commentary


@pytest.mark.parametrize(("count", "noun", "count_word"), [
    (1, "account", "one"), (2, "accounts", "two"),
])
def test_pre2k_commentary_counts_identified_accounts(monkeypatch, count, noun, count_word):
    output = f"Found {count} pre-created computer accounts\nSuccessfully obtained TGT"
    monkeypatch.setattr(pre2k, "run_check", lambda *_args: output)
    _, findings = pre2k.pre2k_check("dc", "user", "password")
    assert f"{count_word} pre-created computer\n{noun}" in findings[0].commentary
    assert "Ticket Granting Ticket (TGT)" in findings[0].commentary
    assert "A Kerberos TGT was successfully" in findings[0].evidence[-1]


def test_delegation_parses_enabled_accounts_from_netexec_table(monkeypatch):
    prefix = "LDAP 10.0.0.1 389 DC01 "

    def row(account, kind, delegation, rights):
        return prefix + f"{account:<15} {kind:<15} {delegation:<35} {rights}"

    output = "\n".join([
        prefix + "[+] EXAMPLE\\user:[REDACTED]",
        row("AccountName", "AccountType", "DelegationType", "DelegationRightsTo"),
        row("-" * 15, "-" * 15, "-" * 35, "-" * 40),
        row("SQL Service", "Person", "Unconstrained", "N/A"),
        row("very-long-service-account", "Person", "Unconstrained", "N/A"),
        row("fifteenlettersx  service", "Person", "Unconstrained", "N/A"),
        row("SQL Service", "Person", "Constrained w/ Protocol Transition", "HTTP/web"),
        row("DC01$", "Computer", "Unconstrained", "N/A"),
        row("AzureADKerberos$", "Computer", "Unconstrained", "N/A"),
        row("other", "Person", "Constrained", "HTTP/web"),
        row("rbcd", "Computer", "Resource-Based Constrained", "server$"),
    ])
    calls = []

    def run(name, command):
        calls.append((name, command))
        return output

    monkeypatch.setattr(delegations, "run_check", run)
    monkeypatch.setattr(delegations, "load_dc_hostnames", lambda: ["dc01.example.test"])
    monkeypatch.setattr(delegations, "get_privileged_users", lambda *_args: {"sql service"})
    result, findings = delegations.delegation_check("dc", "user", "pw")
    assert len(calls) == 1 and calls[0][1][-1] == "--find-delegation"
    assert result == {
        "unconstrained": [
            "SQL Service", "fifteenlettersx  service", "very-long-service-account"
        ],
        "protocol_transition": ["SQL Service"],
    }
    assert [finding.id for finding in findings] == ["DELEG-001", "DELEG-002", "DELEG-003"]
    assert "one privileged delegated account was identified." in findings[-1].evidence[-1]


@pytest.mark.parametrize("output", [
    "",
    "LDAP 10.0.0.1 389 DC01 [-] [REMOVED] Use --find-delegation instead.",
    "LDAP 10.0.0.1 389 DC01 [-] LDAP search failed",
    "LDAP 10.0.0.1 389 DC01 AccountName     AccountType     DelegationType"
    "                      DelegationRightsTo\n"
    "LDAP 10.0.0.1 389 DC01 malformed table row",
    "LDAP 10.0.0.1 389 DC01 [-] No entries found!\n"
    "LDAP 10.0.0.1 389 DC01 Skipping item, cannot process due to error",
])
def test_delegation_rejects_failed_or_unrecognised_output(output):
    with pytest.raises(CheckExecutionError):
        delegations.parse_delegation_output(output)


def test_delegation_accepts_netexec_empty_result():
    output = "LDAP 10.0.0.1 389 DC01 [-] No entries found!"
    assert delegations.parse_delegation_output(output) == (set(), set())


def test_delegation_parses_older_dynamic_width_netexec_table():
    prefix = "LDAP 10.0.0.1 389 DC01 "
    header = f"{'AccountName':<30} {'AccountType':<16} {'DelegationType':<35} DelegationRightsTo"
    row = f"{'service account':<30} {'Person':<16} {'Unconstrained':<35} N/A"
    assert delegations.parse_delegation_output(prefix + header + "\n" + prefix + row) == (
        {"service account"}, set()
    )


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
        "coercion_dcs": {
            "DC1": ["DFSCoerce", "MSEven", "PetitPotam", "WebDAV"], "DC2": ["other"],
        } if has_finding else {},
        "spooler_dcs": [],
    })

    @contextmanager
    def evidence():
        yield [
            CheckEvidence(
                "coercion-plus", ["nxc", "-p", "***", "-M", "coerce_plus"],
                "SMB 192.0.2.1 445 DC1 VULNERABLE, DFSCoerce\n"
                "SMB 192.0.2.2 445 DC2 VULNERABLE, other\n"
                "SMB 192.0.2.1 445 DC1 VULNERABLE, MSEven\n"
                "SMB 192.0.2.1 445 DC1 VULNERABLE, PetitPotam",
                "",
            ),
            CheckEvidence(
                "coercion-webdav", ["nxc", "-p", "***", "-M", "webdav"],
                "SMB 192.0.2.1 445 DC1 WebClient Service enabled\n"
                "SMB 192.0.2.2 445 DC2 WebClient Service enabled",
                "",
            ),
        ]

    monkeypatch.setattr(privileged, "capture_check_evidence", evidence)
    privileged.run_coercion_checks("password")
    text = output.getvalue()
    assert ("Command Evidence" in text) is has_finding
    assert ("VULNERABLE, PetitPotam" in text) is has_finding
    assert ("VULNERABLE, DFSCoerce" in text) is has_finding
    assert ("VULNERABLE, MSEven" in text) is has_finding
    assert ("DC1 WebClient Service enabled" in text) is has_finding
    assert "DC2 VULNERABLE" not in text
    assert "DC2 WebClient Service enabled" not in text
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
    finding = recorded_findings[0]
    assert finding.affected_assets == ["dc1", "dc2", "dc3"]
    assert "identified three\nsystems exposing" in finding.commentary
    markdown = format_finding_sections(finding)["Evidence"]
    assert "Domain Controller (DC)" in finding.commentary
    assert "The following DCs exposed" in markdown
    assert "| Hostname | Coercion Methods |" in markdown
    assert "| DC1 | PetitPotam, WebDAV |" in markdown
    assert "| DC2 | DFSCoerce |" in markdown
    assert "1. Domain Controller" not in markdown
    html = render_html([finding])
    assert "<th>Hostname</th><th>Coercion Methods</th>" in html
    assert "<td>DC1</td><td>PetitPotam, WebDAV</td>" in html
    assert "<td>DC2</td><td>DFSCoerce</td>" in html
    assert "Print Spooler" in html


def test_coercion_evidence_table_escapes_cells():
    finding = privileged.load_finding("coercion", "COERCE-001")
    finding.evidence_table = privileged.EvidenceTable(
        "Detected methods:", ("Hostname", "Coercion Methods"), [("DC|1", "<method>")]
    )
    markdown = format_finding_sections(finding)["Evidence"]
    assert r"| DC\|1 | &lt;method&gt; |" in markdown
    html = render_html([finding])
    assert "<td>DC|1</td><td>&lt;method&gt;</td>" in html


def test_spooler_only_coercion_shows_matching_service_evidence(monkeypatch):
    output = io.StringIO()
    findings = []
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda *_args: None)
    monkeypatch.setattr(privileged, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(privileged, "record_findings", findings.extend)
    monkeypatch.setattr(privileged, "require_session", lambda: {"standard_user": "user"})
    monkeypatch.setattr(privileged, "coercion_check", lambda *_args: {
        "coercion_dcs": {}, "spooler_dcs": ["DC1"],
    })

    @contextmanager
    def evidence():
        yield [CheckEvidence(
            "coercion-spooler", ["nxc", "-M", "spooler"],
            "SMB 192.0.2.1 445 DC1 Spooler service enabled\n"
            "SMB 192.0.2.2 445 DC2 Spooler service enabled", "",
        )]

    monkeypatch.setattr(privileged, "capture_check_evidence", evidence)
    privileged.run_coercion_checks("pw")
    assert "DC1 Spooler service enabled" in output.getvalue()
    assert "DC2 Spooler service enabled" not in output.getvalue()
    assert findings[0].evidence_table is None
    assert "DC1" in findings[0].evidence[0]
    assert "identified one\nsystem exposing" in findings[0].commentary


def test_coercion_commentary_combines_explanation_and_examples():
    finding = privileged.load_finding("coercion", "COERCE-001")
    commentary = format_finding_sections(finding)["Commentary"]
    assert (
        "attacker-controlled systems. Techniques such as PrinterBug" in commentary
    )


@pytest.mark.parametrize("kind", ["local_admin", "adcs", "pre2k", "tombstone"])
def test_other_checks_show_known_affected_objects(monkeypatch, kind):
    module = (
        privileged if kind == "adcs"
        else unauthenticated if kind == "tombstone"
        else policy
    )
    output = io.StringIO()
    recorded_findings = []
    monkeypatch.setattr(module, "console", Console(file=output, width=160))
    monkeypatch.setattr(module, "print_section", lambda *_args: None)
    monkeypatch.setattr(module, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(module, "record_findings", recorded_findings.extend)
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
    if kind == "local_admin":
        assert "one\ndomain-joined system" in recorded_findings[0].commentary
        assert "one host permitted" in recorded_findings[0].evidence[-1]
    if kind == "tombstone":
        assert "on one Domain Controller" in recorded_findings[0].commentary
        assert "one deleted object on 'DC1'" in recorded_findings[0].evidence[0]


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
