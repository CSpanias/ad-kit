import io
from contextlib import nullcontext

from rich.console import Console

from ad_kit.checks import smb
from ad_kit.commands.checks import unauthenticated
from ad_kit.reporting import results


def test_smb_scopes_anonymous_users_and_displays_enumeration_status(monkeypatch, tmp_path):
    results.reset()
    calls = []
    evidence = []
    share_hosts = []
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "capture_check_evidence", lambda: nullcontext(evidence))
    monkeypatch.setattr(unauthenticated, "track_items", lambda items, _label: items)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "192.0.2.1",
        "standard_user": "user",
        "domain_computers_exported": True,
    })
    monkeypatch.setattr(
        unauthenticated, "load_domain_computers", lambda: ["DC.EXAMPLE", "HOST", "NO-NULL", "FAIL"]
    )
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: ["dc.example"])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        unauthenticated, "smb_share_access_check",
        lambda host, *_args: (share_hosts.append(host) or [], []),
    )

    def run(name, command):
        calls.append((name, command))
        host = command[2]
        if name.startswith("smb-anonymous"):
            if host == "FAIL":
                output_text = "SMB FAIL 445 FAIL [-] Error enumerating shares: ACCESS_DENIED"
            else:
                output_text = (
                    "SMB host 445 HOST Enumerated shares\n"
                    "SMB host 445 HOST Share Permissions Remark\n"
                    "SMB host 445 HOST ----- ----------- ------\n"
                    "SMB host 445 HOST public READ files\n"
                )
                if host == "DC.EXAMPLE":
                    output_text += (
                        "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
                        "SMB dc 445 DC alice 2024-01-01 0 example\n"
                        "SMB dc 445 DC Enumerated 1 local users: EXAMPLE\n"
                    )
        else:
            marker = "" if host == "NO-NULL" else " (Null Auth:True)"
            output_text = f"SMB host 445 HOST (signing:True) (SMBv1:False){marker}"
        evidence.append(unauthenticated.CheckEvidence(name, command, output_text, ""))
        return output_text

    monkeypatch.setattr(smb, "run_check", run)
    unauthenticated.run_smb_checks("secret")

    enumeration = {command[2]: command for name, command in calls if "anonymous" in name}
    assert "--users" in enumeration["DC.EXAMPLE"]
    assert "--users" not in enumeration["HOST"]
    assert "--users" not in enumeration["FAIL"]
    assert "NO-NULL" not in enumeration
    table_output = output.getvalue()
    dc_section = table_output.split("SMB Checks - Domain Controllers", 1)[1].split(
        "SMB Checks - Hosts", 1
    )[0]
    host_section = table_output.split("SMB Checks - Hosts", 1)[1]
    assert "Null Session" in dc_section
    assert "Null Session" in host_section
    assert any("DC.EXAMPLE" in line and "Permitted" in line for line in dc_section.splitlines())
    assert any(
        "NO-NULL" in line and "Not confirmed" in line for line in host_section.splitlines()
    )
    assert "Anon Users" not in host_section
    assert "Not attempted" in table_output
    assert "Incomplete" in table_output
    assert table_output.count("Anonymous evidence - ") == 1
    assert "Anonymous evidence - DC.EXAMPLE\n\n$ nxc smb" in table_output
    assert sorted(share_hosts) == ["DC.EXAMPLE", "FAIL", "HOST", "NO-NULL"]
    assert any("FAIL" in entry and "share enumeration" in entry for entry in results._incomplete)
    finding = next(finding for finding in results._findings if finding.id == "SMB-003")
    assert any("DC.EXAMPLE" in entry and "account(s)" in entry for entry in finding.evidence)
    assert not any("'HOST'" in entry and "account(s)" in entry for entry in finding.evidence)
    results.reset()


def test_anonymous_counts_require_evidence_of_completion():
    assert smb._parse_share_count("SMB host 445 HOST [-] Error enumerating shares") is None
    assert smb._parse_share_count(
        "SMB host 445 HOST Enumerated shares\n"
        "SMB host 445 HOST Share Permissions Remark\n"
        "SMB host 445 HOST ----- ----------- ------\n"
    ) == 0
    assert smb._parse_user_count("SMB dc 445 DC [-] Error enumerating domain user(s)") == (
        None, False
    )
    assert smb._parse_user_count("SMB dc 445 DC Enumerated 0 local users: EXAMPLE") == (
        0, True
    )


def test_smb_invalid_configuration_values_remain_unknown(monkeypatch):
    monkeypatch.setattr(
        smb, "run_check", lambda *_args: "SMB host 445 HOST (signing:unknown) (SMBv1:unknown)"
    )
    result = smb.smb_configuration_check("host", "dc")
    assert result["signing"] == "[yellow]⚠ Unknown[/yellow]"
    assert result["smbv1"] == "[yellow]⚠ Unknown[/yellow]"
    assert result["null_auth"] is None


def test_partial_user_results_remain_visible_and_are_marked_incomplete():
    output = (
        "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
        "SMB dc 445 DC alice 2024-01-01 0 example\n"
        "SMB dc 445 DC [-] Error enumerating domain user(s)\n"
        "SMB dc 445 DC Enumerated 1 local users: EXAMPLE\n"
    )
    count, complete = smb._parse_user_count(output)
    assert (count, complete) == (1, False)
    assert unauthenticated._anonymous_count(count, True, complete=complete) == (
        "Incomplete (1 observed)"
    )


def test_share_failure_preserves_successful_dc_user_enumeration(monkeypatch):
    results.reset()

    def run(name, _command):
        if not name.startswith("smb-anonymous"):
            return "SMB dc 445 DC (signing:True) (SMBv1:False) (Null Auth:True)"
        return (
            "SMB dc 445 DC [-] Error enumerating shares: ACCESS_DENIED\n"
            "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
            "SMB dc 445 DC alice 2024-01-01 0 example\n"
            "SMB dc 445 DC Enumerated 1 local users: EXAMPLE\n"
        )

    monkeypatch.setattr(smb, "run_check", run)
    result = smb.smb_configuration_check("dc", "192.0.2.1", enumerate_users=True)
    assert result["anonymous_shares"] is None
    assert result["anonymous_users"] == 1
    assert result["anonymous_users_complete"]
    assert any("share enumeration" in entry for entry in results._incomplete)
    results.reset()


def test_anonymous_evidence_prefers_users_and_limits_rows(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    users = "".join(
        f"SMB dc 445 DC user{i:02} 2024-01-01 0 example\n" for i in range(12)
    )
    record = unauthenticated.CheckEvidence(
        "smb-anonymous-enumeration-DC",
        ["nxc", "smb", "DC", "-u", "", "-p", "", "--shares", "--users"],
        "SMB dc 445 DC Enumerated shares\n"
        "SMB dc 445 DC Share Permissions Remark\n"
        "SMB dc 445 DC public READ files\n"
        "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
        + users + "SMB dc 445 DC Enumerated 12 local users: EXAMPLE\n",
        "",
    )
    unauthenticated._show_anonymous_evidence(
        [record], [{"host": "DC", "null_auth": True}], "smb"
    )
    text = output.getvalue()
    assert "Anonymous evidence - DC\n\n$ nxc smb" in text
    assert "--users" in text
    assert "user00" in text and "user09" in text
    assert "user10" not in text and "user11" not in text
    assert "2 additional row(s) omitted" in text
    assert "public READ" not in text


def test_anonymous_evidence_falls_back_to_shares_and_preserves_errors(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    record = unauthenticated.CheckEvidence(
        "smb-anonymous-enumeration-DC",
        ["nxc", "smb", "DC", "--shares", "--users"],
        "SMB dc 445 DC [-] Error enumerating domain user(s)\n"
        "SMB dc 445 DC Enumerated shares\n"
        "SMB dc 445 DC Share Permissions Remark\n"
        "SMB dc 445 DC public READ files\n",
        "",
    )
    unauthenticated._show_anonymous_evidence(
        [record], [{"host": "DC", "null_auth": True}], "smb"
    )
    text = output.getvalue()
    assert "Error enumerating domain user" in text
    assert "public READ files" in text


def test_ldap_anonymous_evidence_limits_results_and_marks_missing_rows(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    records = [
        unauthenticated.CheckEvidence(
            "ldap-anonymous-users-DC",
            ["nxc", "ldap", "DC", "-u", "", "-p", "", "--users"],
            "LDAP dc 389 DC Enumerated 12 domain users: EXAMPLE\n"
            "LDAP dc 389 DC -Username- -Last PW Set- -BadPW- -Description-\n"
            + "".join(
                f"LDAP dc 389 DC user{i:02} 2024-01-01 0 example\n" for i in range(12)
            ),
            "",
        )
    ]
    result = [{"dc_hostname": "DC", "anonymous_bind": "[red]✗ Permitted[/red]"}]
    unauthenticated._show_anonymous_evidence(records, result, "ldap")
    text = output.getvalue()
    assert "Anonymous evidence - DC\n\n$ nxc ldap" in text
    assert "Enumerated 12 domain users" in text
    assert "user09" in text and "user10" not in text
    assert "2 additional row(s) omitted" in text

    output.seek(0)
    output.truncate()
    records[0] = unauthenticated.CheckEvidence(
        "ldap-anonymous-users-DC", ["nxc", "ldap", "DC", "--users"],
        "LDAP dc 389 DC [-] search denied", "",
    )
    unauthenticated._show_anonymous_evidence(records, result, "ldap")
    assert "search denied" in output.getvalue()
    assert "No user or share rows confirmed" in output.getvalue()


def test_ldap_selects_one_sample_with_users_over_unconfirmed_results(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    records = [
        unauthenticated.CheckEvidence(
            "ldap-anonymous-users-DC1", ["nxc", "ldap", "DC1", "--users"],
            "LDAP dc1 389 DC1 [-] search denied", "",
        ),
        unauthenticated.CheckEvidence(
            "ldap-anonymous-users-DC2", ["nxc", "ldap", "DC2", "--users"],
            "LDAP dc2 389 DC2 -Username- -Last PW Set- -BadPW- -Description-\n"
            "LDAP dc2 389 DC2 alice 2024-01-01 0 example\n", "",
        ),
        unauthenticated.CheckEvidence(
            "ldap-anonymous-users-DC3", ["nxc", "ldap", "DC3", "--users"],
            "LDAP dc3 389 DC3 -Username- -Last PW Set- -BadPW- -Description-\n"
            "LDAP dc3 389 DC3 bob 2024-01-01 0 example\n", "",
        ),
    ]
    results = [
        {"dc_hostname": host, "anonymous_bind": "[red]✗ Permitted[/red]"}
        for host in ("DC1", "DC2", "DC3")
    ]
    unauthenticated._show_anonymous_evidence(records, results, "ldap")
    text = output.getvalue()
    assert text.count("Anonymous evidence - ") == 1
    assert "Anonymous evidence - DC2" in text
    assert "alice" in text and "bob" not in text


def test_smb_sample_falls_back_to_host_with_share_rows(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    records = [
        unauthenticated.CheckEvidence(
            "smb-anonymous-enumeration-DC", ["nxc", "smb", "DC", "--users"],
            "SMB dc 445 DC [-] access denied", "",
        ),
        unauthenticated.CheckEvidence(
            "smb-anonymous-enumeration-HOST", ["nxc", "smb", "HOST", "--shares"],
            "SMB host 445 HOST Enumerated shares\n"
            "SMB host 445 HOST Share Permissions Remark\n"
            "SMB host 445 HOST public READ files\n", "",
        ),
    ]
    targets = [{"host": host, "null_auth": True} for host in ("DC", "HOST")]
    unauthenticated._show_anonymous_evidence(records, targets, "smb")
    text = output.getvalue()
    assert text.count("Anonymous evidence - ") == 1
    assert "Anonymous evidence - HOST" in text
    assert "public READ files" in text
