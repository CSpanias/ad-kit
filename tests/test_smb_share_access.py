import io
import threading
from contextlib import nullcontext

import pytest
from rich.console import Console

from ad_kit.checks import smb
from ad_kit.commands.checks import unauthenticated
from ad_kit.core import util
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.reporting import html, json, markdown, results


def _share_output(rows, permission_width=22):
    prefix = "SMB host 445 HOST "
    lines = [
        prefix + "Enumerated shares",
        prefix + f"{'Share':<15} {'Permissions':<{permission_width}} Remark",
        prefix + f"{'-----':<15} {'-----------':<{permission_width}} ------",
    ]
    lines.extend(
        prefix + f"{name:<15} {permissions:<{permission_width}} {remark}"
        for name, permissions, remark in rows
    )
    return "\n".join(lines)


@pytest.mark.parametrize("permission_width", [15, 22])
def test_share_access_uses_one_command_and_ignores_inaccessible_shares(
    monkeypatch, permission_width
):
    calls = []

    def run(name, command, sensitive_values, *, show_progress):
        calls.append((name, command, sensitive_values, show_progress))
        return _share_output([
            ("Compressor In", "READ", "A remark"),
            ("Compressor Out", "READ,WRITE", "Output"),
            ("Long READ share name", "READ,WRITE (ACL)", ""),
            ("[Write Only]", "WRITE (SUBDIR)", ""),
            ("Denied", "", "READ"),
            ("Very long denied WRITE", "", "WRITE                  remark"),
            ("Denied too", "", ""),
        ], permission_width)

    monkeypatch.setattr(smb, "run_check", run)
    shares, errors = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert not errors
    assert shares == [
        {"name": "Compressor In", "permissions": ("READ",)},
        {"name": "Compressor Out", "permissions": ("READ", "WRITE")},
        {"name": "Long READ share name", "permissions": ("READ", "WRITE (ACL)")},
        {"name": "[Write Only]", "permissions": ("WRITE (SUBDIR)",)},
    ]
    assert len(calls) == 1
    assert calls[0][1][calls[0][1].index("--shares") + 1] == "--dns-server"
    assert calls[0][2:] == (["secret"], False)


def test_share_access_parses_netexec_table_with_type_column(monkeypatch):
    output = "\n".join([
        "SMB 192.168.77.10 445 DC01 [*] Enumerated shares",
        "SMB 192.168.77.10 445 DC01 Share           Permissions     Type       Remark",
        "SMB 192.168.77.10 445 DC01 -----           -----------     ----       ------",
        "SMB 192.168.77.10 445 DC01 ADKIT-Logon     READ,WRITE      DISKTREE   ",
        "SMB 192.168.77.10 445 DC01 ADMIN$                          DISKTREE   Remote Admin",
        "SMB 192.168.77.10 445 DC01 IPC$            READ            IPC        Remote IPC",
        "SMB 192.168.77.10 445 DC01 NETLOGON        READ            DISKTREE   Logon server",
    ])
    monkeypatch.setattr(smb, "run_check", lambda *_args, **_kwargs: output)

    shares, errors = smb.smb_share_access_check("dc", "dc", "user", "secret")

    assert errors == []
    assert shares == [
        {"name": "ADKIT-Logon", "permissions": ("READ", "WRITE")},
        {"name": "IPC$", "permissions": ("READ",)},
        {"name": "NETLOGON", "permissions": ("READ",)},
    ]


def test_share_access_reports_command_failure(monkeypatch):
    def run(name, command, sensitive_values, *, show_progress):
        raise CheckExecutionError(name, [], returncode=1)

    monkeypatch.setattr(smb, "run_check", run)
    shares, errors = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert shares == []
    assert errors and "smb-share-access-host" in errors[0]


def test_share_access_preserves_confirmed_results_and_reports_unknown_rows(monkeypatch):
    def run(name, command, sensitive_values, *, show_progress):
        return _share_output([
            ("Read Only", "READ", ""),
            ("share", "UNEXPECTED", ""),
            ("other", "UNKNOWN (try '--no-smbv1')", ""),
        ])

    monkeypatch.setattr(smb, "run_check", run)
    shares, errors = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert shares == [{"name": "Read Only", "permissions": ("READ",)}]
    assert any("Could not parse" in error for error in errors)
    assert any("Unknown share permissions" in error for error in errors)


def test_share_access_reports_missing_table(monkeypatch):
    monkeypatch.setattr(
        smb, "run_check",
        lambda *_args, **_kwargs: "SMB host 445 HOST [-] Error enumerating shares",
    )
    shares, errors = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert shares == []
    assert errors and "No complete share listing" in errors[0]


def test_share_access_marks_partial_table_incomplete(monkeypatch):
    output = (
        _share_output([("Read Only", "READ", "")])
        + "\nSMB host 445 HOST [-] share enumeration failed"
    )
    monkeypatch.setattr(smb, "run_check", lambda *_args, **_kwargs: output)
    shares, errors = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert shares == [{"name": "Read Only", "permissions": ("READ",)}]
    assert errors and "reported an error" in errors[0]


def test_share_access_does_not_guess_ambiguous_permissions(monkeypatch):
    output = _share_output([
        ("Long share with READ            in name", "WRITE", "remark"),
    ], permission_width=15)
    monkeypatch.setattr(smb, "run_check", lambda *_args, **_kwargs: output)
    shares, errors = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert shares == []
    assert errors and "Could not parse" in errors[0]


@pytest.mark.parametrize("workers", [1, 4, 16])
def test_parallel_share_checks_are_bounded_and_keep_host_order(monkeypatch, workers):
    barrier = threading.Barrier(workers)
    lock = threading.Lock()
    active = 0
    peak = 0
    started = []
    main_thread = threading.get_ident()
    progress_threads = []
    hosts = [f"host-{i}" for i in range(workers + 1)]

    def check(host, *_args):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            started.append(host)
        if host in hosts[:workers]:
            barrier.wait(timeout=5)
        with lock:
            active -= 1
        return [{"name": host, "permissions": ("READ",)}], []

    def track(items, _label):
        for item in items:
            progress_threads.append(threading.get_ident())
            yield item

    monkeypatch.setattr(unauthenticated, "smb_share_access_check", check)
    monkeypatch.setattr(util, "track_items", track)
    with util.check_workers(workers):
        checked = unauthenticated._check_share_access(
            [*hosts, hosts[0].upper() + "."], "dc", "user", "secret"
        )
    assert peak == workers
    assert sorted(started) == sorted(hosts)
    assert [host for host, _, _ in checked] == hosts
    assert progress_threads == [main_thread] * len(hosts)


def test_share_table_and_finding_only_include_write_related_permissions(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    messages = []
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=200))
    monkeypatch.setattr(unauthenticated, "print_info", messages.append)
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "track_items", lambda items, _label: items)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(
        unauthenticated, "load_domain_computers", lambda: ["host-A", "host-B", "host-C"]
    )
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        unauthenticated, "smb_configuration_check", lambda host, *_args, **_kwargs: {
            "host": host, "signing": "[green]✓ Enabled[/green]",
            "smbv1": "[green]✓ Disabled[/green]", "null_auth": False,
            "anonymous_shares": None, "anonymous_users": None, "anonymous_incomplete": [],
        },
    )
    shares = {
        "host-A": [
            {"name": "ipc$", "permissions": ("READ",)},
            {"name": "PrInT$", "permissions": ("READ",)},
            {"name": "Read Only", "permissions": ("READ",)},
            {"name": "SYSVOL", "permissions": ("READ",)},
            {"name": "Writable", "permissions": ("READ", "WRITE")},
            {"name": "Shared", "permissions": ("READ", "WRITE")},
            {"name": "Reversed", "permissions": ("WRITE", "READ")},
            {"name": "ACL", "permissions": ("READ", "WRITE (ACL)")},
        ],
        "host-B": [
            {"name": "IPC$", "permissions": ("READ", "WRITE")},
            {"name": "print$", "permissions": ("WRITE (SUBDIR)",)},
        ],
        "host-C": [
            {"name": "IPC$", "permissions": ("READ",)},
            {"name": "print$", "permissions": ("READ",)},
        ],
    }
    monkeypatch.setattr(
        unauthenticated, "smb_share_access_check", lambda host, *_args: (shares[host], [])
    )

    unauthenticated.run_smb_checks("secret")
    table = output.getvalue().split("SMB Checks - Share Access", 1)[1]
    assert "Shares" in table and "Permissions" in table
    assert table.count("host-A") == 1 and table.count("host-B") == 1
    assert "host-C" not in table and "ipc$" not in table and "PrInT$" not in table
    assert any("Read Only, SYSVOL" in line and "READ" in line for line in table.splitlines())
    assert any("Writable, Shared" in line and "READ, WRITE" in line for line in table.splitlines())
    assert any("ACL" in line and "WRITE (ACL)" in line for line in table.splitlines())
    assert any("IPC$" in line and "READ, WRITE" in line for line in table.splitlines())
    assert any("print$" in line and "WRITE (SUBDIR)" in line for line in table.splitlines())
    assert len(messages) == 1
    assert "Read-only IPC$ and print$ shares are omitted" in messages[0]
    assert "evidence directory" in messages[0]
    finding = next(finding for finding in results._findings if finding.id == "SMB-004")
    assert "identified multiple Server Message Block (SMB) shares" in finding.commentary
    assert "access control list (ACL)" in markdown.format_paragraphs(finding.commentary)
    assert finding.evidence_table is not None
    assert finding.evidence_table.columns == ("Hostname or IP address", "Share(s)", "Permissions")
    assert finding.evidence_table.rows == [
        ("host-A", "Writable, Shared, Reversed", "READ, WRITE"),
        ("host-A", "ACL", "READ, WRITE (ACL)"),
        ("host-B", "IPC$", "READ, WRITE"),
        ("host-B", "print$", "WRITE (SUBDIR)"),
    ]
    assert finding.affected_assets == ["host-A", "host-B"]
    rendered = markdown.format_findings([finding])
    assert "Affected Assets" not in rendered
    assert "**Note:** The check does not create or modify files." in rendered
    assert "| Hostname or IP address | Share(s) | Permissions |" in rendered
    assert "| --- | --- | --- |" in rendered
    assert "| host-A | Writable, Shared, Reversed | READ, WRITE |" in rendered
    assert "| host-B | print$ | WRITE (SUBDIR) |" in rendered
    report = html.render_html([finding])
    assert "<strong>Note:</strong>" in report
    assert "<th>Hostname or IP address</th><th>Share(s)</th><th>Permissions</th>" in report
    assert "<td>Writable, Shared, Reversed</td>" in report
    assert "Affected Assets" not in report
    json.reset()
    json.collect([finding])
    assert "Note: The check does not create or modify files." in (
        json.get_findings()[0]["description"]
    )
    json.reset()
    results.reset()


@pytest.mark.parametrize(("permissions", "expected"), [
    (("WRITE (ACL)",), True),
    (("READ",), False),
])
def test_share_finding_single_share_or_none(monkeypatch, tmp_path, permissions, expected):
    results.reset()
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["192.0.2.10"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "smb_configuration_check", lambda *_args, **_kwargs: {
        "host": "192.0.2.10", "signing": "[green]✓ Enabled[/green]",
        "smbv1": "[green]✓ Disabled[/green]", "null_auth": False,
        "anonymous_shares": None, "anonymous_users": None, "anonymous_incomplete": [],
    })
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: (
        [{"name": "share", "permissions": permissions}], []
    ))
    unauthenticated.run_smb_checks("secret")
    finding = next((f for f in results._findings if f.id == "SMB-004"), None)
    assert (finding is not None) is expected
    if finding:
        assert "identified one Server Message Block (SMB) share" in finding.commentary
        assert "Where effective file-write access is available" in finding.commentary
        assert "not necessarily grant direct file-write access" in (
            markdown.format_paragraphs(finding.commentary_note)
        )
        assert finding.evidence_table is not None
        assert finding.evidence_table.rows == [("192.0.2.10", "share", "WRITE (ACL)")]
    results.reset()


@pytest.mark.parametrize("incomplete", [False, True])
def test_hidden_default_shares_do_not_imply_no_access(monkeypatch, tmp_path, incomplete):
    results.reset()
    messages = []
    monkeypatch.setattr(unauthenticated, "print_info", messages.append)
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["host"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "smb_configuration_check", lambda *_args, **_kwargs: {
        "host": "host", "signing": "[green]✓ Enabled[/green]", "smbv1": "[green]✓ Disabled[/green]",
        "null_auth": False, "anonymous_shares": None, "anonymous_users": None,
        "anonymous_incomplete": [],
    })
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: (
        [{"name": "IPC$", "permissions": ("READ",)}], ["incomplete"] if incomplete else []
    ))

    unauthenticated.run_smb_checks("secret")

    assert ("No reportable SMB shares found for the Standard User." in messages) is not incomplete
    assert any("Read-only IPC$ and print$ shares are omitted" in message for message in messages)
    results.reset()
