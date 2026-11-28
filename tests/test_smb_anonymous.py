import io
import re
import threading
from contextlib import nullcontext

import pytest
from rich.console import Console

from ad_kit.checks import smb
from ad_kit.commands.checks import unauthenticated
from ad_kit.core import console as console_helpers
from ad_kit.core import util
from ad_kit.core.checks import append_captured_evidence
from ad_kit.reporting import html, markdown, results


def test_smb_scopes_anonymous_users_and_displays_enumeration_status(monkeypatch, tmp_path):
    results.reset()
    calls = []
    share_hosts = []
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
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

    def run(name, command, **_kwargs):
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
                if name.startswith("smb-anonymous-users") and host == "DC.EXAMPLE":
                    output_text += (
                        "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
                        "SMB dc 445 DC alice 2024-01-01 0 example\n"
                        "SMB dc 445 DC Enumerated 1 local users: EXAMPLE\n"
                    )
        else:
            auth = (
                "[-] EXAMPLE\\: STATUS_LOGON_FAILURE"
                if host == "NO-NULL"
                else "[+] EXAMPLE\\:"
            )
            output_text = (
                "SMB host 445 HOST (signing:True) (SMBv1:False)\n"
                f"SMB host 445 HOST {auth}"
            )
        append_captured_evidence([
            unauthenticated.CheckEvidence(name, command, output_text, "")
        ])
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
    assert "Anonymous Enumeration" in dc_section
    assert "Anonymous Enumeration" in host_section
    assert any("DC.EXAMPLE" in line and "Permitted" in line for line in dc_section.splitlines())
    assert "NO-NULL" not in host_section
    assert re.search(r"Anonymous Enumeration\s+│\s+1\s+│\s+2\s+│\s+0\s+│", host_section)
    assert "Anon Users" not in host_section
    assert "Not attempted" not in table_output
    assert table_output.count("Anonymous evidence - ") == 1
    assert "Anonymous evidence - DC.EXAMPLE\n\n$ nxc smb" in dc_section
    assert "[+] EXAMPLE\\:" not in dc_section
    assert "--shares --dns-server" in dc_section
    assert "--users --dns-server" in dc_section
    assert sorted(share_hosts) == ["DC.EXAMPLE", "FAIL", "HOST", "NO-NULL"]
    assert not any("FAIL" in entry and "share enumeration" in entry for entry in results._incomplete)
    finding = next(finding for finding in results._findings if finding.id == "SMB-003")
    assert any("DC.EXAMPLE" in entry and "one account," in entry for entry in finding.evidence)
    assert any("DC.EXAMPLE" in entry and "one share." in entry for entry in finding.evidence)
    assert not any("'HOST'" in entry and "account" in entry for entry in finding.evidence)
    results.reset()


@pytest.mark.parametrize(("observations", "expected_columns", "statuses"), [
    ([(0, 0, True, False, False)], [], ["Disabled"]),
    ([(0, 0, True, True, False)], [], ["Disabled"]),
    ([(None, None, False, False, False)], [], ["Disabled"]),
    ([(0, 2, True, True, False)], ["Anon Users"], ["Permitted"]),
    ([(3, 0, True, True, False)], ["Anon Shares"], ["Permitted"]),
    ([(3, 2, True, True, False)], ["Anon Shares", "Anon Users"], ["Permitted"]),
    ([(0, 2, True, True, False), (3, 0, True, True, False)],
     ["Anon Shares", "Anon Users"], ["Permitted", "Permitted"]),
    ([(None, None, False, True, False)], [], ["Disabled"]),
    ([(None, None, False, None, False)], [], ["Disabled"]),
    ([(0, None, False, True, False)], [], ["Disabled"]),
    ([(None, 2, False, True, False)], ["Anon Users"], ["Permitted"]),
    ([(2, None, False, None, True)], ["Anon Shares"], ["Permitted"]),
    ([(0, 0, True, None, True)], [], ["Disabled"]),
])
def test_dc_table_only_shows_observed_enumeration_columns(
    monkeypatch, tmp_path, observations, expected_columns, statuses
):
    results.reset()
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "", "domain_computers_exported": True,
    })
    hosts = [f"DC{i}" for i in range(len(observations))]
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: hosts)
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: hosts)
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)

    def configuration(host, _dc, *, enumerate_users):
        shares, users, complete, null_auth, guest = observations[int(host[2:])]
        return {
            "host": host, "signing": "[green]✓ Enabled[/green]",
            "smbv1": "[green]✓ Disabled[/green]", "null_auth": null_auth,
            "guest_auth": guest, "anonymous_shares": shares, "anonymous_users": users,
            "anonymous_users_complete": complete, "anonymous_incomplete": [],
        }

    monkeypatch.setattr(unauthenticated, "smb_configuration_check", configuration)
    unauthenticated.run_smb_checks()
    table = output.getvalue().split("SMB Checks - Domain Controllers", 1)[1].split(
        "SMB Checks - Hosts", 1
    )[0]
    assert "Anonymous Enumeration" in table
    for column in ("Anon Shares", "Anon Users"):
        assert (column in table) == (column in expected_columns)
    for host, status, (shares, users, *_rest) in zip(hosts, statuses, observations):
        row = next(line for line in table.splitlines() if host in line)
        assert status in row
        cells = [cell.strip() for cell in row.split("│")[1:-1]]
        counts = cells[4:]
        expected_counts = [
            count for column, count in (("Anon Shares", shares), ("Anon Users", users))
            if column in expected_columns
        ]
        assert len(counts) == len(expected_counts)
        for cell, count in zip(counts, expected_counts):
            if count is not None:
                assert re.search(rf"\b{count}\b", cell)
    results.reset()


def test_dc_enumeration_is_unknown_when_empty_results_are_incomplete():
    result = {
        "null_auth": True, "guest_auth": False, "anonymous_shares": 0,
        "anonymous_users": 0, "anonymous_users_complete": True,
        "anonymous_incomplete": ["Share enumeration reported an error"],
    }
    assert unauthenticated._anonymous_enumeration_status(result, enumerate_users=True) == "Disabled"


def test_anonymous_counts_require_evidence_of_completion():
    assert unauthenticated._anonymous_count(None, False) == "[green]✓ Denied[/green]"
    assert unauthenticated._anonymous_count(None, None) == "Incomplete"
    assert unauthenticated._anonymous_count(None, True) == "Incomplete"
    assert unauthenticated._anonymous_count(0, True) == "0"
    assert smb._parse_share_count("SMB host 445 HOST [-] Error enumerating shares") is None
    assert smb._parse_share_count(
        "SMB host 445 HOST Enumerated shares\n"
        "SMB host 445 HOST Share Permissions Remark\n"
        "SMB host 445 HOST ----- ----------- ------\n"
    ) == 0
    assert smb._parse_share_count(
        "SMB host 445 HOST Enumerated shares\n"
        "SMB host 445 HOST Share Permissions Remark\n"
        "SMB host 445 HOST [-] Error enumerating shares: ACCESS_DENIED\n"
    ) is None
    assert smb._parse_user_count("SMB dc 445 DC [-] Error enumerating domain user(s)") == (
        None, False
    )
    assert smb._parse_user_count("SMB dc 445 DC Enumerated 0 local users: EXAMPLE") == (
        0, True
    )


def test_smb_configuration_runs_in_parallel_and_keeps_sample_evidence(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    dc_barrier = threading.Barrier(2)
    host_barrier = threading.Barrier(2)
    share_hosts = []
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(
        unauthenticated, "load_domain_computers",
        lambda: ["HOST1", "DC1", "HOST2", "DC2", "DOWN", "dc1."],
    )
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: ["dc1.", "dc2"])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        unauthenticated, "smb_share_access_check",
        lambda host, *_args: (share_hosts.append(host) or [], []),
    )

    def run(name, command, **_kwargs):
        if name in {"smb-DC1", "smb-DC2"}:
            dc_barrier.wait(timeout=5)
        if name in {"smb-HOST1", "smb-HOST2"}:
            displayed = output.getvalue()
            assert "SMB Checks - Domain Controllers" in displayed
            assert "DC1" in displayed and "DC2" in displayed
            host_barrier.wait(timeout=5)
        if name == "smb-DC1":
            text = (
                "SMB dc 445 DC (signing:True) (SMBv1:False)\n"
                "SMB dc 445 DC [+] EXAMPLE\\:"
            )
        elif name in {"smb-DC2", "smb-HOST1", "smb-HOST2"}:
            text = (
                "SMB host 445 HOST (signing:False) (SMBv1:False)\n"
                "SMB host 445 HOST [-] EXAMPLE\\: STATUS_LOGON_FAILURE"
            )
        elif name == "smb-anonymous-users-DC1":
            text = (
                "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
                "SMB dc 445 DC alice 2024-01-01 0 example\n"
                "SMB dc 445 DC Enumerated 1 local users: EXAMPLE\n"
            )
        else:
            text = ""
        append_captured_evidence([unauthenticated.CheckEvidence(name, command, text, "")])
        return text

    monkeypatch.setattr(smb, "run_check", run)
    with util.check_workers(2):
        unauthenticated.run_smb_checks("secret")
    text = output.getvalue()
    assert "Anonymous evidence - DC1" in text and "alice" in text
    assert "HOST1" not in text and "HOST2" not in text and "DOWN" not in text
    assert sorted(share_hosts) == ["DC1", "DC2", "DOWN", "HOST1", "HOST2"]
    assert any("SMB configuration - DOWN" in entry for entry in results._incomplete)
    assert any("share enumeration" in entry for entry in results._incomplete)
    results.reset()


def test_smb_host_summary_counts_verified_and_incomplete_results(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "", "domain_computers_exported": True,
    })
    monkeypatch.setattr(
        unauthenticated, "load_domain_computers",
        lambda: ["A", "B", "C", "D", "E", "F", "G", "H", "a."],
    )
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)

    def configuration(host, _dc, *, enumerate_users):
        assert not enumerate_users
        if host == "F":
            raise unauthenticated.CheckExecutionError("smb-F", [], stderr="failed")
        return {
            "host": host,
            "signing": (
                "[red]✗ Disabled[/red]" if host == "B"
                else "[yellow]⚠ Unknown[/yellow]" if host == "C"
                else "[green]✓ Enabled[/green]"
            ),
            "smbv1": "[red]✗ Enabled[/red]" if host == "B" else "[green]✓ Disabled[/green]",
            "null_auth": True if host in {"A", "C", "E"} else False if host == "B" else None,
            "guest_auth": host in {"D", "H"},
            "anonymous_shares": {"A": 3, "D": 1, "E": 0}.get(host),
            "anonymous_users": None,
            "anonymous_incomplete": ["enumeration failed"] if host in {"C", "H"} else [],
        }

    monkeypatch.setattr(unauthenticated, "smb_configuration_check", configuration)
    unauthenticated.run_smb_checks()
    summary = output.getvalue().split("SMB Checks - Hosts", 1)[1].split(
        "SMB Checks - Share Access", 1
    )[0]
    for label, enabled, disabled, unknown in [
        ("SMB Signing", 5, 1, 2),
        ("SMBv1", 1, 6, 1),
        ("Anonymous Enumeration", 2, 5, 1),
    ]:
        assert re.search(
            rf"{re.escape(label)}\s+│\s+{enabled}\s+│\s+{disabled}\s+│\s+{unknown}\s+│",
            summary,
        )
    assert any("SMB configuration - F" in entry for entry in results._incomplete)
    assert any("SMB anonymous enumeration - C" in entry for entry in results._incomplete)
    finding = next(finding for finding in results._findings if finding.id == "SMB-003")
    assert sorted(finding.affected_assets) == ["A", "D"]
    results.reset()


@pytest.mark.parametrize(("unsigned", "controllers", "expected"), [
    ([], ["DC"], None),
    (["HOST"], [], "one system did not require SMB signing."),
    (["HOST", "SERVER"], [], "two systems did not require SMB signing."),
    (
        ["HOST", "DC."],
        ["dc"],
        "two systems, including one domain controller, did not require SMB signing.",
    ),
    (
        ["DC1", "DC2", "HOST"],
        ["dc1.", "dc2"],
        "three systems, including two domain controllers, did not require SMB signing.",
    ),
    ([f"HOST{i}" for i in range(9)], [], "nine systems did not require SMB signing."),
    ([f"HOST{i}" for i in range(10)], [], "10 systems did not require SMB signing."),
])
def test_smb_signing_finding_summarises_affected_systems(
    monkeypatch, tmp_path, unsigned, controllers, expected
):
    results.reset()
    hosts = unsigned + ["UNKNOWN"]
    monkeypatch.setattr(unauthenticated, "console", Console(file=io.StringIO(), width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda *_args: None)
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: hosts)
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: controllers)
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "smb_configuration_check", lambda host, *_args, **_kw: {
        "host": host,
        "signing": "[red]✗ Disabled[/red]" if host in unsigned else "[yellow]⚠ Unknown[/yellow]",
        "smbv1": "[green]✓ Disabled[/green]",
        "null_auth": False, "anonymous_shares": None, "anonymous_users": None,
        "anonymous_incomplete": [],
    })
    unauthenticated.run_smb_checks()
    finding = next((f for f in results._findings if f.id == "SMB-001"), None)
    if expected is None:
        assert finding is None
    else:
        assert finding is not None
        commentary = markdown.format_paragraphs(finding.commentary)
        assert expected in commentary
        assert "NTLM authentication" in commentary
        assert sorted(finding.affected_assets) == sorted(unsigned)
        assert "Affected Assets" not in markdown.format_findings([finding])
        assert "Affected Assets" not in html.render_html([finding])
    results.reset()


@pytest.mark.parametrize(("enabled", "controllers", "expected"), [
    ([], ["DC"], None),
    (["HOST"], [], "one system had SMBv1 enabled."),
    (["HOST", "SERVER"], [], "two systems had SMBv1 enabled."),
    (
        ["HOST", "DC."],
        ["dc"],
        "two systems, including one domain controller, had SMBv1 enabled.",
    ),
    (
        ["DC1", "DC2", "HOST"],
        ["dc1.", "dc2"],
        "three systems, including two domain controllers, had SMBv1 enabled.",
    ),
    (
        ["HOST", "DC1", "DC2", "DC3", "DC4"],
        ["DC1", "DC2"],
        "five systems, including two domain controllers, had SMBv1 enabled.",
    ),
])
def test_smbv1_finding_summarises_affected_systems(
    monkeypatch, tmp_path, enabled, controllers, expected
):
    results.reset()
    hosts = enabled + ["UNKNOWN"]
    monkeypatch.setattr(unauthenticated, "console", Console(file=io.StringIO(), width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda *_args: None)
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: hosts)
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: controllers)
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "smb_configuration_check", lambda host, *_args, **_kw: {
        "host": host,
        "signing": "[green]✓ Enabled[/green]",
        "smbv1": "[red]✗ Enabled[/red]" if host in enabled else "[yellow]⚠ Unknown[/yellow]",
        "null_auth": False, "anonymous_shares": None, "anonymous_users": None,
        "anonymous_incomplete": [],
    })
    unauthenticated.run_smb_checks()
    finding = next((f for f in results._findings if f.id == "SMB-002"), None)
    if expected is None:
        assert finding is None
    else:
        assert finding is not None
        commentary = markdown.format_paragraphs(finding.commentary)
        assert expected in commentary
        assert "does not by itself establish" in commentary
        assert sorted(finding.affected_assets) == sorted(enabled)
        assert "Affected Assets" not in markdown.format_findings([finding])
        assert "Affected Assets" not in html.render_html([finding])
    results.reset()


def test_smb_partial_share_results_are_retained_and_marked_incomplete(monkeypatch):
    def run(name, *_args, **_kwargs):
        if name.startswith("smb-anonymous"):
            return (
                "SMB host 445 HOST Enumerated shares\n"
                "SMB host 445 HOST Share Permissions Remark\n"
                "SMB host 445 HOST public READ files\n"
                "SMB host 445 HOST [-] Error enumerating shares: ACCESS_DENIED\n"
            )
        return (
            "SMB host 445 HOST (signing:True) (SMBv1:False)\n"
            "SMB host 445 HOST [+] EXAMPLE\\:"
        )

    monkeypatch.setattr(smb, "run_check", run)
    result = smb.smb_configuration_check("host", "dc")
    assert result["anonymous_shares"] == 1
    assert result["anonymous_incomplete"] == ["Share enumeration reported an error; see evidence"]
    assert (
        unauthenticated._anonymous_enumeration_status(result, enumerate_users=False) == "Permitted"
    )


@pytest.mark.parametrize(("shares", "users", "complete", "guest", "expected"), [
    (None, None, False, False, "Disabled"),
    (0, None, False, False, "Disabled"),
    (None, 1, False, False, "Permitted"),
    (None, 0, False, False, "Disabled"),
    (0, 0, True, False, "Disabled"),
    (1, None, False, True, "Permitted"),
    (None, None, False, True, "Disabled"),
])
def test_anonymous_enumeration_distinguishes_complete_partial_and_guest(
    shares, users, complete, guest, expected
):
    result = {
        "anonymous_shares": shares, "anonymous_users": users,
        "anonymous_users_complete": complete, "null_auth": None if guest else True,
        "guest_auth": guest,
        "anonymous_incomplete": [],
    }
    assert unauthenticated._anonymous_enumeration_status(result, enumerate_users=True) == expected


@pytest.mark.parametrize("dc_evidence_shown", [False, True])
def test_smb_password_prompt_is_separated_from_host_summary(
    monkeypatch, tmp_path, dc_evidence_shown
):
    results.reset()
    output = io.StringIO()
    console = Console(file=output, width=160)
    monkeypatch.setattr(unauthenticated, "console", console)
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["HOST"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    def show_evidence(*_args):
        if not dc_evidence_shown:
            console.print()
        return dc_evidence_shown

    monkeypatch.setattr(unauthenticated, "_show_anonymous_evidence", show_evidence)
    monkeypatch.setattr(unauthenticated, "smb_configuration_check", lambda *_args, **_kwargs: {
        "host": "HOST", "signing": "[green]✓ Enabled[/green]",
        "smbv1": "[green]✓ Disabled[/green]", "null_auth": False,
        "anonymous_shares": None, "anonymous_users": None, "anonymous_incomplete": [],
    })
    monkeypatch.setattr(
        unauthenticated, "authenticate_standard_user",
        lambda **_kwargs: console.print("Enter the Standard User password:") or "secret",
    )
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: ([], []))
    unauthenticated.run_smb_checks()
    assert "\n\nEnter the Standard User password:" in output.getvalue()
    results.reset()


def test_smb_host_evidence_follows_host_table_when_no_dc_finding(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["DC", "HOST"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: ["DC"])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)

    def run(name, command, **_kwargs):
        if name == "smb-anonymous-enumeration-HOST":
            text = (
                "SMB host 445 HOST Enumerated shares\n"
                "SMB host 445 HOST Share Permissions Remark\n"
                "SMB host 445 HOST public READ files\n"
            )
        else:
            auth = "[-] EXAMPLE\\: STATUS_LOGON_FAILURE" if command[2] == "DC" else "[+] EXAMPLE\\:"
            text = f"SMB host 445 HOST (signing:True) (SMBv1:False)\nSMB host 445 HOST {auth}"
        append_captured_evidence([unauthenticated.CheckEvidence(name, command, text, "")])
        return text

    monkeypatch.setattr(smb, "run_check", run)
    unauthenticated.run_smb_checks("secret")
    text = output.getvalue()
    assert text.count("Anonymous evidence - ") == 1
    assert text.index("SMB Checks - Hosts") < text.index("Anonymous evidence - HOST")
    results.reset()


def test_smb_null_session_without_enumeration_finding_hides_evidence(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["DC"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: ["DC"])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: ([], []))

    def run(name, command, **_kwargs):
        text = (
            "SMB dc 445 DC [-] access denied"
            if name.startswith("smb-anonymous")
            else (
                "SMB dc 445 DC (signing:True) (SMBv1:False)\n"
                "SMB dc 445 DC [+] EXAMPLE\\:"
            )
        )
        append_captured_evidence([unauthenticated.CheckEvidence(name, command, text, "")])
        return text

    monkeypatch.setattr(smb, "run_check", run)
    unauthenticated.run_smb_checks("secret")
    assert "Anonymous evidence -" not in output.getvalue()
    assert not any(finding.id == "SMB-003" for finding in results._findings)
    assert any("SMB anonymous enumeration" in entry for entry in results._incomplete)
    results.reset()


def test_smb_invalid_configuration_values_remain_unknown(monkeypatch):
    monkeypatch.setattr(
        smb, "run_check",
        lambda *_args, **_kwargs: "SMB host 445 HOST (signing:unknown) (SMBv1:unknown)"
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

    def run(name, _command, **_kwargs):
        if not name.startswith("smb-anonymous"):
            return (
                "SMB dc 445 DC (signing:True) (SMBv1:False)\n"
                "SMB dc 445 DC [+] EXAMPLE\\:"
            )
        if name.startswith("smb-anonymous-enumeration"):
            return "SMB dc 445 DC [-] Error enumerating shares: ACCESS_DENIED\n"
        return (
            "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
            "SMB dc 445 DC alice 2024-01-01 0 example\n"
            "SMB dc 445 DC Enumerated 1 local users: EXAMPLE\n"
        )

    monkeypatch.setattr(smb, "run_check", run)
    result = smb.smb_configuration_check("dc", "192.0.2.1", enumerate_users=True)
    assert result["anonymous_shares"] == 0
    assert result["anonymous_users"] == 1
    assert result["anonymous_users_complete"]
    assert result["anonymous_incomplete"] == []
    results.reset()


def test_share_command_failure_does_not_prevent_user_enumeration(monkeypatch):
    def run(name, _command, **_kwargs):
        if name.startswith("smb-anonymous-enumeration"):
            raise smb.CheckExecutionError(name, [], stderr="connection failed")
        if name.startswith("smb-anonymous-users"):
            return (
                "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
                "SMB dc 445 DC alice 2024-01-01 0 example\n"
                "SMB dc 445 DC Enumerated 1 local users: EXAMPLE\n"
            )
        return "SMB dc 445 DC (signing:True) (SMBv1:False)\nSMB dc 445 DC [+] EXAMPLE\\:"

    monkeypatch.setattr(smb, "run_check", run)
    result = smb.smb_configuration_check("dc", "192.0.2.1", enumerate_users=True)
    assert result["anonymous_shares"] is None
    assert result["anonymous_users"] == 1
    assert result["anonymous_users_complete"]
    assert len(result["anonymous_incomplete"]) == 1


@pytest.mark.parametrize(("users_output", "user_count", "incomplete"), [
    ("", 0, False),
    (
        "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
        "SMB dc 445 DC alice 2024-01-01 0 example\n"
        "SMB dc 445 DC Enumerated 1 local users: EXAMPLE\n",
        1, False,
    ),
    ("SMB dc 445 DC [-] Connection reset\n", None, True),
])
def test_share_denied_retries_users_without_false_coverage_gap(
    monkeypatch, users_output, user_count, incomplete
):
    calls = []

    def run(name, command, **_kwargs):
        calls.append(command)
        auth = (
            "SMB dc 445 DC (signing:True) (SMBv1:False)\n"
            "SMB dc 445 DC [+] EXAMPLE\\:********\n"
        )
        if name.startswith("smb-anonymous-enumeration"):
            return auth + "SMB dc 445 DC [-] Error enumerating shares: STATUS_ACCESS_DENIED\n"
        if name.startswith("smb-anonymous-users"):
            return auth + users_output
        return auth

    monkeypatch.setattr(smb, "run_check", run)
    result = smb.smb_configuration_check("dc", "192.0.2.1", enumerate_users=True)

    assert result["anonymous_shares"] == 0
    assert result["anonymous_users"] == user_count
    assert bool(result["anonymous_incomplete"]) is incomplete
    assert "--users" in calls[-1] and "--shares" not in calls[-1]
    assert unauthenticated._anonymous_enumeration_status(
        result, enumerate_users=True
    ) == ("Permitted" if user_count else "Disabled")


def test_denied_anonymous_enumeration_does_not_create_coverage_gap(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["DC"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: ["DC"])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: ([], []))

    def run(name, _command, **_kwargs):
        auth = (
            "SMB dc 445 DC (signing:True) (SMBv1:False)\n"
            "SMB dc 445 DC [+] EXAMPLE\\:********\n"
        )
        if name.startswith("smb-anonymous-enumeration"):
            return auth + "SMB dc 445 DC [-] Error enumerating shares: STATUS_ACCESS_DENIED\n"
        return auth

    monkeypatch.setattr(smb, "run_check", run)
    unauthenticated.run_smb_checks("secret")

    assert "Disabled" in output.getvalue()
    assert "SMB anonymous enumeration could not be completed" not in output.getvalue()
    assert not results._incomplete
    results.reset()


def test_anonymous_evidence_includes_users_from_separate_check(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    records = [
        unauthenticated.CheckEvidence("smb-DC", ["nxc", "smb", "DC"], "", ""),
        unauthenticated.CheckEvidence(
            "smb-anonymous-enumeration-DC", ["nxc", "smb", "DC", "--shares", "--users"],
            "SMB dc 445 DC [-] Error enumerating shares: STATUS_ACCESS_DENIED", "",
        ),
        unauthenticated.CheckEvidence(
            "smb-anonymous-users-DC", ["nxc", "smb", "DC", "--users"],
            "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
            "SMB dc 445 DC alice 2024-01-01 0 example\n"
            "SMB dc 445 DC Enumerated 1 local users: EXAMPLE", "",
        ),
    ]
    assert unauthenticated._show_anonymous_evidence(
        records, [{"host": "DC", "null_auth": True}], "smb"
    )
    assert "$ nxc smb DC --users" in output.getvalue()
    assert "alice" in output.getvalue()
    assert "--shares" not in output.getvalue()
    assert "Error enumerating shares" not in output.getvalue()


@pytest.mark.parametrize(
    ("authentication", "expected_null", "expected_guest", "enumerates"),
    [
        ("[+] EXAMPLE\\:", True, False, True),
        ("[+] EXAMPLE\\: (Guest)", None, True, True),
        ("[-] EXAMPLE\\: STATUS_LOGON_FAILURE", False, False, False),
        ("[-] EXAMPLE\\: STATUS_ACCESS_DENIED", False, False, False),
        ("[-] EXAMPLE\\: STATUS_NOT_SUPPORTED", None, False, False),
        ("[-] EXAMPLE\\: Connection reset", None, False, False),
        ("", None, False, False),
    ],
)
def test_smb_explicit_empty_login_distinguishes_outcomes(
    monkeypatch, authentication, expected_null, expected_guest, enumerates
):
    calls = []

    def run(name, command, **_kwargs):
        calls.append((name, command))
        if name.startswith("smb-anonymous"):
            return (
                "SMB host 445 HOST Enumerated shares\n"
                "SMB host 445 HOST Share Permissions Remark\n"
            )
        return (
            "SMB host 445 HOST (signing:True) (SMBv1:False) (Null Auth:True)\n"
            f"SMB host 445 HOST {authentication}"
        )

    monkeypatch.setattr(smb, "run_check", run)
    result = smb.smb_configuration_check("host", "dc")
    assert calls[0][1] == [
        "nxc", "smb", "host", "-u", "", "-p", "", "--dns-server", "dc",
    ]
    assert result["null_auth"] is expected_null
    assert result["guest_auth"] is expected_guest
    assert (len(calls) == 2) is enumerates


def test_guest_session_is_visible_and_included_in_enumeration_finding(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["HOST"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: ([], []))

    def run(name, command, **_kwargs):
        if name.startswith("smb-anonymous"):
            text = (
                "SMB host 445 HOST Enumerated shares\n"
                "SMB host 445 HOST Share Permissions Remark\n"
                "SMB host 445 HOST public READ files\n"
            )
        else:
            text = (
                "SMB host 445 HOST (signing:True) (SMBv1:False)\n"
                "SMB host 445 HOST [+] EXAMPLE\\: (Guest)"
            )
        append_captured_evidence([unauthenticated.CheckEvidence(name, command, text, "")])
        return text

    monkeypatch.setattr(smb, "run_check", run)
    unauthenticated.run_smb_checks("pw")
    assert re.search(
        r"Anonymous Enumeration\s+│\s+1\s+│\s+0\s+│\s+0\s+│",
        output.getvalue(),
    )
    assert "Anonymous evidence - HOST" in output.getvalue()
    finding = next(finding for finding in results._findings if finding.id == "SMB-003")
    assert any("mapped to Guest" in entry and "'HOST'" in entry for entry in finding.evidence)
    assert "a Guest-mapped SMB session established with empty credentials" in finding.commentary
    assert "allowed enumeration of\nshare names on one system" in finding.commentary
    assert not results._incomplete
    results.reset()


@pytest.mark.parametrize(("observations", "expected", "guest_hosts"), [
    ([(2, None, False)], "share names", []),
    ([(None, 3, True)], "user account information", []),
    ([(2, 3, True)], "share names and user account information", []),
    ([(2, None, False), (None, 3, False)], "share names and user account information", []),
    ([(2, None, False), (None, 3, False)], "share names and user account information", ["DC1"]),
    ([(0, 3, False)], "user account information", []),
    ([(2, 0, True)], "share names", []),
    ([(0, 0, True)], None, []),
])
def test_anonymous_finding_commentary_matches_observed_objects(
    monkeypatch, tmp_path, observations, expected, guest_hosts
):
    results.reset()
    monkeypatch.setattr(unauthenticated, "console", Console(file=io.StringIO(), width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda *_args: None)
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "", "domain_computers_exported": True,
    })
    hosts = [f"DC{i}" for i in range(len(observations))]
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: hosts)
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: hosts)
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)

    def configuration(host, _dc, *, enumerate_users):
        shares, users, complete = observations[int(host[2:])]
        return {
            "host": host, "signing": "[green]✓ Enabled[/green]",
            "smbv1": "[green]✓ Disabled[/green]", "null_auth": host not in guest_hosts,
            "guest_auth": host in guest_hosts,
            "anonymous_shares": shares, "anonymous_users": users,
            "anonymous_users_complete": complete, "anonymous_incomplete": [],
        }

    monkeypatch.setattr(unauthenticated, "smb_configuration_check", configuration)
    unauthenticated.run_smb_checks()
    finding = next((finding for finding in results._findings if finding.id == "SMB-003"), None)
    if expected is None:
        assert finding is None
        results.reset()
        return
    assert finding is not None
    count_word = {1: "one", 2: "two"}[len(hosts)]
    assert (
        f"allowed enumeration of\n{expected} on {count_word} "
        f"{'domain controller' if len(hosts) == 1 else 'domain controllers'}."
    ) in finding.commentary
    assert "naming conventions and potential targets for password guessing" in finding.commentary
    assert "share names may indicate the purpose or location of network resources" in (
        markdown.format_paragraphs(finding.commentary)
    )
    assert ("Enumerating share names does not by itself demonstrate access to share contents."
            in finding.commentary) is any(shares for shares, _, _ in observations)
    assert "session setup alone" not in finding.commentary
    if guest_hosts:
        assert "anonymous and Guest-mapped SMB sessions" in finding.commentary
    assert sorted(finding.affected_assets) == hosts
    assert all(any(f"'{host}'" in entry for entry in finding.evidence) for host in hosts)
    formatted = markdown.format_findings([finding])
    report = html.render_html([finding])
    assert "Affected Assets" not in formatted
    assert "### Evidence" not in formatted
    assert "Affected Assets" not in report
    assert "<summary>Evidence</summary>" not in report
    assert "Remediation" in report
    results.reset()


def test_anonymous_evidence_displays_separate_share_and_user_rows(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    users = "".join(
        f"SMB dc 445 DC user{i:02} 2024-01-01 0 example\n" for i in range(12)
    )
    records = [
        unauthenticated.CheckEvidence("smb-DC", ["nxc", "smb", "DC"], "login only", ""),
        unauthenticated.CheckEvidence(
            "smb-anonymous-enumeration-DC", ["nxc", "smb", "DC", "--shares"],
            "SMB dc 445 DC Enumerated shares\n"
            "SMB dc 445 DC Share Permissions Remark\n"
            "SMB dc 445 DC public READ files\n", "",
        ),
        unauthenticated.CheckEvidence(
            "smb-anonymous-users-DC", ["nxc", "smb", "DC", "--users"],
            "SMB dc 445 DC -Username- -Last PW Set- -BadPW- -Description-\n"
            + users + "SMB dc 445 DC Enumerated 12 local users: EXAMPLE\n", "",
        ),
    ]
    unauthenticated._show_anonymous_evidence(
        records, [{"host": "DC", "null_auth": True}], "smb"
    )
    text = output.getvalue()
    assert "Anonymous evidence - DC\n\n$ nxc smb" in text
    assert "$ nxc smb DC --shares" in text
    assert "$ nxc smb DC --users" in text
    assert text.index("--shares") < text.index("--users")
    assert "login only" not in text
    assert "user00" in text and "user09" in text
    assert "user10" not in text and "user11" not in text
    assert "2 additional row(s) omitted" in text
    assert "public READ" in text


def test_anonymous_evidence_shows_partial_shares_and_preserves_errors(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    record = unauthenticated.CheckEvidence(
        "smb-anonymous-enumeration-DC",
        ["nxc", "smb", "DC", "--shares"],
        "SMB dc 445 DC [-] Error enumerating shares\n"
        "SMB dc 445 DC Enumerated shares\n"
        "SMB dc 445 DC Share Permissions Remark\n"
        "SMB dc 445 DC public READ files\n",
        "",
    )
    unauthenticated._show_anonymous_evidence(
        [record], [{"host": "DC", "null_auth": True}], "smb"
    )
    text = output.getvalue()
    assert "Error enumerating shares" in text
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
    monkeypatch.setattr(console_helpers, "console", unauthenticated.console)
    console_helpers.print_section("Password Policy")
    assert "... 2 additional row(s) omitted.\n\n[Password Policy]\n" in output.getvalue()
    assert "... 2 additional row(s) omitted.\n\n\n[Password Policy]" not in output.getvalue()

    output.seek(0)
    output.truncate()
    records[0] = unauthenticated.CheckEvidence(
        "ldap-anonymous-users-DC", ["nxc", "ldap", "DC", "--users"],
        "LDAP dc 389 DC [-] search denied", "",
    )
    unauthenticated._show_anonymous_evidence(records, result, "ldap")
    assert "search denied" in output.getvalue()
    assert "No user or share rows confirmed" in output.getvalue()


def test_missing_anonymous_evidence_leaves_section_spacing_to_heading(monkeypatch):
    output = io.StringIO()
    console = Console(file=output)
    monkeypatch.setattr(unauthenticated, "console", console)
    monkeypatch.setattr(console_helpers, "console", console)
    console.print("Table")
    unauthenticated._show_anonymous_evidence([], [], "ldap")
    console_helpers.print_section("Password Policy")
    assert output.getvalue() == "Table\n\n[Password Policy]\n\n"


def test_anonymous_evidence_separates_records_without_trailing_blank(monkeypatch):
    output = io.StringIO()
    console = Console(file=output, width=200)
    monkeypatch.setattr(unauthenticated, "console", console)
    monkeypatch.setattr(console_helpers, "console", console)
    records = [
        unauthenticated.CheckEvidence("ldap-DC", ["first"], "first output", ""),
        unauthenticated.CheckEvidence("ldap-anonymous-users-DC", ["second"], "denied", ""),
    ]
    unauthenticated._show_anonymous_evidence(
        records, [{"dc_hostname": "DC", "anonymous_bind": "[red]✗ Permitted[/red]"}], "ldap"
    )
    console_helpers.print_section("Next")
    text = output.getvalue()
    assert "first output\n\n$ second\n" in text
    assert "No user or share rows confirmed in this output.\n\n[Next]\n" in text


@pytest.mark.parametrize("with_host", [False, True])
@pytest.mark.parametrize("with_evidence", [False, True])
@pytest.mark.parametrize("needs_auth", [False, True])
def test_smb_progress_and_heading_spacing(
    monkeypatch, tmp_path, with_host, with_evidence, needs_auth
):
    output = io.StringIO()
    console = Console(file=output, width=200)
    monkeypatch.setattr(unauthenticated, "console", console)
    monkeypatch.setattr(console_helpers, "console", console)
    monkeypatch.setattr(unauthenticated, "print_section", console_helpers.print_section)
    monkeypatch.setattr(
        unauthenticated, "progress",
        lambda message: (console.print(f"PROGRESS: {message}") or nullcontext()),
    )
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(
        unauthenticated, "load_domain_computers", lambda: ["DC"] + (["HOST"] if with_host else [])
    )
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: ["DC"])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "record_findings", lambda *_args: None)
    monkeypatch.setattr(unauthenticated, "_check_share_access", lambda *_args: [])
    monkeypatch.setattr(unauthenticated, "print_info", lambda message: console.print(message))
    monkeypatch.setattr(
        unauthenticated, "authenticate_standard_user",
        lambda **_kwargs: (console.print("Authentication succeeded.") or "secret"),
    )

    def configuration(host, *_args, **_kwargs):
        if with_evidence and host == "DC":
            append_captured_evidence([
                unauthenticated.CheckEvidence(
                    "smb-anonymous-enumeration-DC", ["nxc", "smb", "DC", "--shares"],
                    "SMB dc 445 DC Enumerated shares\n"
                    "SMB dc 445 DC Share Permissions Remark\n"
                    "SMB dc 445 DC public READ evidence", "",
                )
            ])
        return {
            "host": host, "signing": "[green]✓ Enabled[/green]",
            "smbv1": "[green]✓ Disabled[/green]", "null_auth": with_evidence and host == "DC",
            "guest_auth": False, "anonymous_shares": 1 if with_evidence and host == "DC" else 0,
            "anonymous_users": 0, "anonymous_incomplete": [],
        }

    monkeypatch.setattr(unauthenticated, "smb_configuration_check", configuration)
    console.print("Previous prompt")
    unauthenticated.run_smb_checks(None if needs_auth else "secret")
    text = output.getvalue()
    assert "Previous prompt\n\nPROGRESS: Checking SMB configuration for Domain Controllers" in text
    if with_evidence:
        following = (
            "PROGRESS: Checking SMB configuration for hosts"
            if with_host else "[SMB Checks - Hosts]"
        )
        assert f"evidence\n\n{following}" in text
    assert "\n\nPROGRESS: Checking SMB share access" in text
    if needs_auth:
        assert "Authentication succeeded.\n\nPROGRESS: Checking SMB share access" in text
    assert "\n\n\n[SMB Checks - Hosts]" not in text


def test_smb_without_hosts_does_not_add_blank_before_next_heading(monkeypatch, tmp_path):
    output = io.StringIO()
    console = Console(file=output)
    monkeypatch.setattr(unauthenticated, "console", console)
    monkeypatch.setattr(console_helpers, "console", console)
    monkeypatch.setattr(unauthenticated, "print_section", console_helpers.print_section)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: [])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "record_findings", lambda *_args: None)
    unauthenticated.run_smb_checks()
    console_helpers.print_section("Next")
    assert "\n\n[Next]\n" in output.getvalue()
    assert "\n\n\n[Next]\n" not in output.getvalue()


def test_tombstone_progress_is_separated_from_previous_output(monkeypatch):
    output = io.StringIO()
    console = Console(file=output)
    monkeypatch.setattr(unauthenticated, "console", console)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user",
    })
    monkeypatch.setattr(
        unauthenticated, "progress",
        lambda message: (console.print(f"PROGRESS: {message}") or nullcontext()),
    )
    monkeypatch.setattr(unauthenticated, "track_items", lambda items, _label: items)

    def stop_after_progress(*_args):
        raise ValueError("stop")

    monkeypatch.setattr(unauthenticated, "tombstone_check", stop_after_progress)
    console.print("Previous output")
    with pytest.raises(ValueError, match="stop"):
        unauthenticated.run_tombstone_checks("secret")
    assert (
        "Previous output\n\nPROGRESS: Checking Standard User access to deleted objects..."
    ) in output.getvalue()


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
