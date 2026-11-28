import io
from contextlib import contextmanager, nullcontext

import pytest
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP, seq_set
from impacket.krb5.types import Principal
from pyasn1.codec.der import encoder
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
from ad_kit.core import privileged as privileged_helpers
from ad_kit.core.checks import CheckEvidence, append_captured_evidence
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import format_counted_commentary
from ad_kit.reporting.html import render_html
from ad_kit.reporting.json import integration_finding
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
    monkeypatch.setattr(kerberoast, "run_check", lambda *_args, **_kwargs: output)
    monkeypatch.setattr(kerberoast, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        kerberoast, "get_account_privileged_groups",
        lambda *_args: {"websvc": ["Domain Admins", "DNSAdmins"]},
    )

    result, findings = kerberoast.kerberoast_check("dc", "example.test", "user", "pw")
    assert result["accounts"] == ["SQL Service", "websvc"]
    assert result["account_count"] == 2
    assert result["privileged_groups"] == {"websvc": ["Domain Admins", "DNSAdmins"]}
    assert [finding.id for finding in findings] == ["KERB-001", "KERB-002"]
    assert "identified\ntwo accounts associated" in findings[0].commentary
    assert "identified one\nprivileged account associated" in findings[1].commentary
    assert "two Kerberoastable accounts were identified." in findings[0].evidence[-1]
    assert "one privileged Kerberoastable account was identified." in findings[1].evidence[-1]
    assert any("Domain Admins, DNSAdmins" in entry for entry in findings[1].evidence)
    for finding in findings:
        assert "Service Principal Names (SPNs)" in finding.commentary
        assert all("Service Principal Name" not in entry for entry in finding.evidence)
        assert any("SPN" in entry for entry in finding.evidence)
        assert "Service Principal Names (SPNs)" in finding.remediation
    assert all("successfully requested" not in entry for f in findings for entry in f.evidence)


def test_kerberoast_rejects_unrecognised_output(monkeypatch, tmp_path):
    monkeypatch.setattr(kerberoast, "run_check", lambda *_args, **_kwargs: "Unexpected output")
    monkeypatch.setattr(kerberoast, "get_artefacts_dir", lambda: tmp_path)
    with pytest.raises(CheckExecutionError, match="Could not parse"):
        kerberoast.kerberoast_check("dc", "example.test", "user", "pw")


def test_kerberoast_empty_result_is_not_a_parse_error(monkeypatch, tmp_path):
    monkeypatch.setattr(kerberoast, "run_check", lambda *_args, **_kwargs: "No entries found!")
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
    monkeypatch.setattr(asreproast, "run_check", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(
        asreproast, "get_account_privileged_groups",
        lambda *_args: {account: ["Domain Admins"] for account in accounts},
    )
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
    output = (
        f"PRE2K 192.0.2.10 389 DC01 [+] Found {count} pre-created computer accounts\n"
        "PRE2K 192.0.2.10 389 DC01 [+] Successfully obtained TGT"
    )
    monkeypatch.setattr(pre2k, "run_check", lambda *_args, **_kwargs: output)
    results, findings = pre2k.pre2k_check("dc", "user", "password")
    assert results["accounts_found"] == count
    assert f"{count_word} pre-created computer\n{noun}" in findings[0].commentary
    assert "Ticket Granting Ticket (TGT)" in findings[0].commentary
    assert "A Kerberos TGT was successfully" in findings[0].evidence[-1]


def test_pre2k_counts_accounts_when_tgt_request_is_denied(monkeypatch):
    output = (
        "PRE2K 192.0.2.10 389 DC01 Pre-created computer account: LAB-PRE2K$\n"
        "PRE2K 192.0.2.10 389 DC01 [+] Found 1 pre-created computer accounts\n"
        "PRE2K 192.0.2.10 389 DC01 [-] Failed to get TGT for "
        "lab-pre2k@adkit.test: KDC_ERR_PREAUTH_FAILED"
    )
    monkeypatch.setattr(pre2k, "run_check", lambda *_args, **_kwargs: output)
    results, findings = pre2k.pre2k_check("dc", "user", "password")
    assert results == {
        "accounts_found": 1,
        "accounts": ["LAB-PRE2K$"],
        "tgt_obtained": False,
        "account_tgts": {"lab-pre2k": "Failed"},
    }
    assert not findings


def test_pre2k_attributes_ticket_results_to_each_account(monkeypatch):
    output = "\n".join([
        "PRE2K dc 389 DC Pre-created computer account: FIRST$",
        "PRE2K dc 389 DC Pre-created computer account: SECOND$",
        "PRE2K dc 389 DC Pre-created computer account: THIRD$",
        "PRE2K dc 389 DC [+] Found 3 pre-created computer accounts",
        "PRE2K dc 389 DC [+] Successfully obtained TGT for first@example.test",
        "PRE2K dc 389 DC [-] Error obtaining TGT for second@example.test: KDC_ERR_ETYPE_NOSUPP",
        "PRE2K dc 389 DC [+] Successfully obtained TGT for 1 (pre-created) computer accounts",
    ])
    monkeypatch.setattr(pre2k, "run_check", lambda *_args, **_kwargs: output)
    results, _ = pre2k.pre2k_check("dc", "user", "password")
    assert results["account_tgts"] == {"first": "Successful", "second": "Error"}
    assert results["accounts"] == ["FIRST$", "SECOND$", "THIRD$"]


def test_pre2k_shows_each_account_and_its_ticket_result(monkeypatch, tmp_path):
    output = io.StringIO()
    monkeypatch.setattr(policy, "console", Console(file=output, width=160))
    monkeypatch.setattr(policy, "print_section", lambda *_args: None)
    monkeypatch.setattr(policy, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(policy, "record_findings", lambda *_args: None)
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain": "example.test",
        "dc_controllers": [{"ip": "dc", "hostname": "dc.example.test"}],
    })
    monkeypatch.setattr(policy, "get_evidence_dir", lambda: tmp_path)
    monkeypatch.setattr(policy, "validate_pre2k_ldap", lambda *_args: (True, ["validated"], ""))
    monkeypatch.setattr(policy, "pre2k_check", lambda *_args: ({
        "accounts": ["FIRST$", "SECOND$", "THIRD$"],
        "account_tgts": {"first": "Successful", "second": "Failed"},
    }, []))
    policy.run_pre2k_checks("pw")
    text = output.getvalue()
    assert "FIRST$" in text and "Successful" in text
    assert "SECOND$" in text and "Failed" in text
    assert "THIRD$" in text and "Unknown" in text
    assert "Accounts Identified" not in text


def _pre2k_ticket(client="LONG-COMPUTER-NAME$", realm="EXAMPLE.TEST"):
    response = AS_REP()
    response["pvno"] = 5
    response["msg-type"] = constants.ApplicationTagNumbers.AS_REP.value
    response["crealm"] = realm
    seq_set(
        response, "cname",
        Principal(client, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1,
    )
    ticket = response["ticket"]
    ticket["tkt-vno"] = 5
    ticket["realm"] = realm
    seq_set(
        ticket, "sname",
        Principal(f"krbtgt/{realm}", type=constants.PrincipalNameType.NT_SRV_INST.value)
        .components_to_asn1,
    )
    ticket["enc-part"]["etype"] = 18
    ticket["enc-part"]["cipher"] = b"ticket"
    response["enc-part"]["etype"] = 18
    response["enc-part"]["cipher"] = b"encrypted"
    return encoder.encode(response)


def test_pre2k_uses_obtained_tgt_for_ldap_bind(monkeypatch):
    ticket, cipher, session_key = _pre2k_ticket(), object(), object()
    calls = []

    def get_tgt(principal, password, domain, lmhash, nthash, *, kdcHost):
        calls.append(("tgt", str(principal), password, domain, lmhash, nthash, kdcHost))
        return ticket, cipher, object(), session_key

    class Connection:
        def __init__(self, url, *, dstIp):
            calls.append(("connect", url, dstIp))

        def kerberosLogin(self, user, password, **kwargs):
            calls.append(("bind", user, password, kwargs))
            return True

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(pre2k, "getKerberosTGT", get_tgt)
    monkeypatch.setattr(pre2k, "LDAPConnection", Connection)
    success, lines, reason = pre2k.validate_pre2k_ldap(
        "LONG-COMPUTER-NAME$", "example.test", "192.0.2.1", "dc.example.test"
    )
    assert success and not reason
    assert calls[0] == (
        "tgt", "long-computer-name", "long-computer-", "example.test", "", "", "192.0.2.1",
    )
    assert calls[1] == ("connect", "ldap://dc.example.test", "192.0.2.1")
    assert calls[2][1:3] == ("LONG-COMPUTER-NAME$", "")
    assert calls[2][3]["TGT"] == {"KDC_REP": ticket, "cipher": cipher, "sessionKey": session_key}
    assert calls[2][3]["useCache"] is False
    assert calls[3] == ("close",)
    assert any("LDAP authentication succeeded" in line for line in lines)
    assert "long-computer-" not in "\n".join(lines).replace("long-computer-name", "")


@pytest.mark.parametrize("stage", ["tgt", "ldap", "ldap-unconfirmed"])
def test_pre2k_validation_failures_are_explicit_and_redacted(monkeypatch, stage):
    closed = []

    def get_tgt(*_args, **_kwargs):
        if stage == "tgt":
            raise OSError("KDC failed for lab-pre2k")
        return _pre2k_ticket("lab-pre2k$"), object(), object(), object()

    class Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        def kerberosLogin(self, *_args, **_kwargs):
            if stage == "ldap":
                raise OSError("LDAP rejected lab-pre2k")
            return False

        def close(self):
            closed.append(True)

    monkeypatch.setattr(pre2k, "getKerberosTGT", get_tgt)
    monkeypatch.setattr(pre2k, "LDAPConnection", Connection)
    success, lines, reason = pre2k.validate_pre2k_ldap(
        "LAB-PRE2K$", "example.test", "dc", "dc.example.test"
    )
    assert not success and reason
    assert "lab-pre2k" not in reason
    assert "LDAP authentication succeeded" not in "\n".join(lines)
    assert closed == ([] if stage == "tgt" else [True])


@pytest.mark.parametrize(("client", "realm"), [
    ("OTHER$", "EXAMPLE.TEST"), ("LAB-PRE2K$", "OTHER.TEST"),
])
def test_pre2k_validation_rejects_mismatched_ticket_identity(monkeypatch, client, realm):
    monkeypatch.setattr(
        pre2k, "getKerberosTGT",
        lambda *_args, **_kwargs: (_pre2k_ticket(client, realm), object(), object(), object()),
    )
    monkeypatch.setattr(
        pre2k, "LDAPConnection", lambda *_args, **_kwargs: pytest.fail("Unexpected LDAP bind")
    )
    success, lines, reason = pre2k.validate_pre2k_ldap(
        "LAB-PRE2K$", "example.test", "dc", "dc.example.test"
    )
    assert not success and "principal did not match" in reason
    assert "LDAP authentication succeeded" not in "\n".join(lines)


def test_pre2k_validation_does_not_expose_malformed_ticket_data(monkeypatch):
    monkeypatch.setattr(
        pre2k, "getKerberosTGT",
        lambda *_args, **_kwargs: (b"secret-ticket-data", object(), object(), object()),
    )
    success, lines, reason = pre2k.validate_pre2k_ldap(
        "LAB-PRE2K$", "example.test", "dc", "dc.example.test"
    )
    assert not success and "Invalid Kerberos or LDAP response" in reason
    assert "secret-ticket-data" not in "\n".join(lines)


def test_pre2k_command_evidence_and_validation_are_reported(monkeypatch, tmp_path):
    output = io.StringIO()
    console = Console(file=output, width=200)
    monkeypatch.setattr(policy, "console", console)
    monkeypatch.setattr(
        policy, "print_section", lambda title: console.print(f"[{title}]", markup=False)
    )
    monkeypatch.setattr(policy, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(policy, "get_evidence_dir", lambda: tmp_path)
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "192.0.2.1", "standard_user": "user", "domain": "example.test",
        "dc_controllers": [
            {"ip": "192.0.2.2", "hostname": "wrong.example.test"},
            {"ip": "192.0.2.1", "hostname": "dc.example.test"},
        ],
    })
    finding = Finding("PRE2K-001", "Pre2k", "Comment", "Fix")
    recorded, incomplete, validations = [], [], []

    def check(*_args):
        append_captured_evidence([CheckEvidence(
            "pre2k", ["nxc", "ldap", "dc", "-p", "[REDACTED]", "-M", "pre2k"],
            "PRE2K dc 389 DC Pre-created computer account: PC1$\n"
            "PRE2K dc 389 DC [+] Found 2 pre-created computer accounts\n"
            "PRE2K dc 389 DC [+] Successfully obtained TGT for pc1@example.test\n"
            "PRE2K dc 389 DC [+] Successfully obtained TGT for pc2@example.test\n", "",
        )])
        return {
            "accounts": ["PC1$", "PC2$", "PC3$"],
            "account_tgts": {"pc1": "Successful", "pc2": "Successful", "pc3": "Failed"},
        }, [finding]

    def validate(account, domain, ip, hostname):
        validations.append((account, domain, ip, hostname))
        if account == "PC2$":
            return False, ["PC2 LDAP failed"], "LDAP failed"
        return True, ["PC1 TGT obtained", "PC1 LDAP authentication succeeded"], ""

    monkeypatch.setattr(policy, "pre2k_check", check)
    monkeypatch.setattr(policy, "validate_pre2k_ldap", validate)
    monkeypatch.setattr(policy, "record_findings", recorded.extend)
    monkeypatch.setattr(policy, "record_incomplete", lambda *args: incomplete.append(args))
    policy.run_pre2k_checks("secret")
    text = output.getvalue()
    assert [row[0] for row in validations] == ["PC1$", "PC2$"]
    assert all(row[3] == "dc.example.test" for row in validations)
    assert "LDAP Validation" in text and "Unknown" in text
    assert "$ nxc ldap dc -p '[REDACTED]' -M pre2k" in text
    assert "Successfully obtained TGT for pc1@example.test" in text
    assert "Pre-created computer account: PC1$" not in text
    assert "PC1 LDAP authentication succeeded" in text and "PC2 LDAP failed" in text
    assert incomplete == [("Pre2K LDAP validation", "PC2$", "LDAP failed")]
    assert recorded == [finding] and "`PC1$` authenticated to LDAP" in finding.evidence[0]
    saved = (tmp_path / "pre2k-ldap-validation.txt").read_text(encoding="utf-8")
    assert "PC1 TGT obtained" in saved and "PC2 LDAP failed" in saved
    assert "secret" not in saved


def test_pre2k_without_matching_dc_hostname_preserves_tgt_finding(monkeypatch, tmp_path):
    output = io.StringIO()
    monkeypatch.setattr(policy, "console", Console(file=output, width=160))
    monkeypatch.setattr(policy, "print_section", lambda *_args: None)
    monkeypatch.setattr(policy, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(policy, "get_evidence_dir", lambda: tmp_path)
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "192.0.2.1", "domain": "example.test", "standard_user": "user",
        "dc_controllers": [{"ip": "192.0.2.2", "hostname": "wrong.example.test"}],
    })
    finding = Finding("PRE2K-001", "Pre2k", "Comment", "Fix")
    monkeypatch.setattr(policy, "pre2k_check", lambda *_args: ({
        "accounts": ["PC1$"], "tgt_obtained": True, "account_tgts": {"pc1": "Successful"},
    }, [finding]))
    monkeypatch.setattr(
        policy, "validate_pre2k_ldap",
        lambda *_args: pytest.fail("Must not authenticate to an unrelated DC"),
    )
    recorded, incomplete = [], []
    monkeypatch.setattr(policy, "record_findings", recorded.extend)
    monkeypatch.setattr(policy, "record_incomplete", lambda *args: incomplete.append(args))
    policy.run_pre2k_checks("secret")
    assert recorded == [finding]
    assert incomplete and "hostname" in incomplete[0][2]
    assert "Unknown" in output.getvalue()
    assert "hostname" in (tmp_path / "pre2k-ldap-validation.txt").read_text(encoding="utf-8")


def test_pre2k_unattributed_tgt_records_incomplete(monkeypatch):
    monkeypatch.setattr(policy, "console", Console(file=io.StringIO(), width=160))
    monkeypatch.setattr(policy, "print_section", lambda *_args: None)
    monkeypatch.setattr(policy, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user",
    })
    monkeypatch.setattr(policy, "pre2k_check", lambda *_args: ({
        "accounts": ["PC1$"], "tgt_obtained": True, "account_tgts": {},
    }, []))
    incomplete = []
    monkeypatch.setattr(policy, "record_incomplete", lambda *args: incomplete.append(args))
    monkeypatch.setattr(policy, "record_findings", lambda *_args: None)
    policy.run_pre2k_checks("secret")
    assert incomplete and "did not identify a matching account" in incomplete[0][2]


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
        row("rbcd", "Computer", "Resource-Based Constrained", "server$"),
        row("rbcd", "Computer", "Resource-Based Constrained", "other server$"),
        row("poppy", "Person", "Resource-Based Constrained", "freya"),
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
        "resource_based": [
            ("poppy", "freya"), ("rbcd", "other server$"), ("rbcd", "server$")
        ],
    }
    assert [finding.id for finding in findings] == [
        "DELEG-001", "DELEG-002", "DELEG-004", "DELEG-003"
    ]
    assert "one privileged delegated account was identified." in findings[-1].evidence[-1]
    rbcd_finding = findings[2]
    assert rbcd_finding.evidence_in_commentary
    assert len(rbcd_finding.evidence) == 3
    assert "`poppy`" in rbcd_finding.evidence[0] and "`freya`" in rbcd_finding.evidence[0]


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
    assert delegations.parse_delegation_output(output) == (set(), set(), set())


def test_rbcd_only_is_recorded_with_principal_and_resource(monkeypatch):
    prefix = "LDAP 192.0.2.1 389 DC01 "
    header = f"{'AccountName':<15} {'AccountType':<15} {'DelegationType':<35} DelegationRightsTo"
    row = f"{'poppy':<15} {'Person':<15} {'Resource-Based Constrained':<35} freya"
    monkeypatch.setattr(
        delegations, "run_check", lambda *_args: prefix + header + "\n" + prefix + row
    )
    monkeypatch.setattr(delegations, "load_dc_hostnames", lambda: ["dc01.example.test"])
    monkeypatch.setattr(delegations, "get_privileged_users", lambda *_args: set())

    result, findings = delegations.delegation_check("dc", "user", "pw")

    assert result["resource_based"] == [("poppy", "freya")]
    assert [finding.id for finding in findings] == ["DELEG-004"]
    assert "poppy" in render_html(findings) and "freya" in render_html(findings)
    description = integration_finding(findings[0])["description"]
    assert "`poppy`" in description and "`freya`" in description


def test_delegation_parses_older_dynamic_width_netexec_table():
    prefix = "LDAP 10.0.0.1 389 DC01 "
    header = f"{'AccountName':<30} {'AccountType':<16} {'DelegationType':<35} DelegationRightsTo"
    row = f"{'service account':<30} {'Person':<16} {'Unconstrained':<35} N/A"
    assert delegations.parse_delegation_output(prefix + header + "\n" + prefix + row) == (
        {"service account"}, set(), set()
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
            {
                "unconstrained": ["service[red]"],
                "protocol_transition": [],
                "resource_based": [("poppy", "freya")],
            }, []
        ))
        module.run_delegation_checks("pw")
        assert "service[red]" in output.getvalue()
        assert "Protocol Transition" in output.getvalue()
        assert "poppy -> freya" in output.getvalue()
    elif kind == "kerberoast":
        monkeypatch.setattr(module, "kerberoast_check", lambda *_args: (
            {"account_count": 1, "accounts": ["svc"], "privileged_groups": {}}, []
        ))
        module.run_kerberoast_checks("pw")
        assert "svc" in output.getvalue()
    else:
        monkeypatch.setattr(module, "require_collected_data", lambda *_args: None)
        monkeypatch.setattr(module, "asreproast_check", lambda *_args: (
            {"account_count": 2, "accounts": ["alice", "admin"]}, []
        ))
        monkeypatch.setattr(
            module, "asreproast_privileged_check",
            lambda *_args: ({"admin": ["Domain Admins", "DNSAdmins"]}, []),
        )
        module.run_asreproast_checks("pw")
        text = output.getvalue()
        assert "alice" in text
        assert text.count("admin") == 1
        assert "Domain Admins" in text and "DNSAdmins" in text


def test_privileged_group_members_parse_accounts_and_fail_closed(monkeypatch):
    monkeypatch.setattr(privileged_helpers, "require_session", lambda: {
        "excluded_users": ["excluded"]
    })
    monkeypatch.setattr(privileged_helpers, "PRIVILEGED_GROUPS", (
        "Domain Admins", "DNSAdmins", "Exchange Windows Permissions",
    ))
    monkeypatch.setattr(privileged_helpers, "track_items", lambda items, _label: items)
    prefix = "LDAP dc 389 DC "

    def run(_name, command):
        group = command[-1]
        if group == "Domain Admins":
            return prefix + "[+] example\\user:********\n" + "\n".join(
                prefix + name for name in ("SQL Service", "ALICE", "excluded")
            )
        if group == "DNSAdmins":
            return prefix + "[+] example\\user:********\n" + prefix + "Alice"
        return (
            prefix + "[+] example\\user:********\n"
            + prefix + f"[-] Group '{group}' not found"
        )

    monkeypatch.setattr(privileged_helpers, "run_check", run)
    groups = privileged_helpers.get_privileged_group_members("dc", "user", "pw")
    assert groups["Domain Admins"] == ["ALICE", "SQL Service"]
    assert groups["Exchange Windows Permissions"] == []
    assert privileged_helpers.get_account_privileged_groups(
        "dc", "user", "pw", ["alice", "SQL Service", "ordinary"]
    ) == {"alice": ["Domain Admins", "DNSAdmins"], "sql service": ["Domain Admins"]}

    monkeypatch.setattr(
        privileged_helpers, "run_check",
        lambda _name, command: prefix + "[+] example\\user:********\n" + prefix
        + f"[-] Group '{command[-1]}' has no members",
    )
    assert all(not members for members in
               privileged_helpers.get_privileged_group_members("dc", "user", "pw").values())

    monkeypatch.setattr(
        privileged_helpers, "run_check",
        lambda *_args: prefix + "[+] example\\user:********\n" + prefix
        + "[-] LDAP search failed",
    )
    with pytest.raises(CheckExecutionError, match="NetExec reported an error"):
        privileged_helpers.get_privileged_group_members("dc", "user", "pw")

    monkeypatch.setattr(
        privileged_helpers, "run_check", lambda *_args: prefix + "[+] example\\user:********"
    )
    with pytest.raises(CheckExecutionError, match="Could not determine group membership"):
        privileged_helpers.get_privileged_group_members("dc", "user", "pw")


@pytest.mark.parametrize("kind", ["asreproast", "kerberoast"])
@pytest.mark.parametrize("groups", [{}, {"admin": ["Domain Admins", "DNSAdmins"]}, None])
def test_roasting_tables_show_groups_only_when_known_or_unknown(monkeypatch, kind, groups):
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
    if kind == "asreproast":
        monkeypatch.setattr(module, "require_collected_data", lambda *_args: None)
        monkeypatch.setattr(module, "asreproast_check", lambda *_args: (
            {"accounts": ["alice", "Admin"], "account_count": 2}, []
        ))
        def lookup(*_args):
            if groups is None:
                raise CheckExecutionError("groups", [], stderr="lookup failed")
            return groups, []
        monkeypatch.setattr(module, "asreproast_privileged_check", lookup)
        monkeypatch.setattr(module, "record_incomplete", lambda *_args: None)
        module.run_asreproast_checks("pw")
    else:
        monkeypatch.setattr(module, "kerberoast_check", lambda *_args: (
            {"accounts": ["alice", "Admin"], "account_count": 2, "privileged_groups": groups}, []
        ))
        module.run_kerberoast_checks("pw")
    text = output.getvalue()
    assert text.count("alice") == 1 and text.count("Admin ") == 1
    assert ("Privileged Group" in text) == (groups is None or bool(groups))
    if groups:
        assert "Domain Admins" in text and "DNSAdmins" in text
    if groups is None:
        assert text.count("Unknown") == 2


@pytest.mark.parametrize("kind", ["asreproast", "kerberoast"])
def test_roasting_tables_show_no_accounts(monkeypatch, kind):
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
    if kind == "asreproast":
        monkeypatch.setattr(module, "require_collected_data", lambda *_args: None)
        monkeypatch.setattr(module, "asreproast_check", lambda *_args: (
            {"accounts": [], "account_count": 0}, []
        ))
        module.run_asreproast_checks("pw")
    else:
        monkeypatch.setattr(module, "kerberoast_check", lambda *_args: (
            {"accounts": [], "account_count": 0, "privileged_groups": {}}, []
        ))
        module.run_kerberoast_checks("pw")
    assert "None found" in output.getvalue()
    assert "Privileged Group" not in output.getvalue()


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
def test_other_checks_show_known_affected_objects(monkeypatch, tmp_path, kind):
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
        monkeypatch.setattr(module, "get_evidence_dir", lambda: tmp_path)
        monkeypatch.setattr(module, "record_incomplete", lambda *_args: None)
        monkeypatch.setattr(module, "pre2k_check", lambda *_args: (
            {
                "accounts_found": 1,
                "accounts": ["OLDPC$"],
                "tgt_obtained": True,
                "account_tgts": {"oldpc": "Successful"},
            },
            [object()],
        ))
        module.run_pre2k_checks("pw")
        expected = "OLDPC$"
        assert "Account" in output.getvalue()
        assert "TGT Acquisition" in output.getvalue()
        assert "Successful" in output.getvalue()
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


def test_local_admin_dc_finding_preserves_affected_hosts(monkeypatch):
    findings = []
    monkeypatch.setattr(policy, "console", Console(file=io.StringIO(), width=160))
    monkeypatch.setattr(policy, "print_section", lambda *_args: None)
    monkeypatch.setattr(policy, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(policy, "record_findings", findings.extend)
    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
        "domain_computers_exported": True,
    })
    monkeypatch.setattr(policy, "local_admin_check", lambda *_args: {
        "hosts": [], "domain_controllers": ["DC1", "DC2"],
    })
    policy.run_local_admin_checks("pw")
    assert findings[0].id == "LA-002"
    assert findings[0].affected_assets == ["DC1", "DC2"]


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
