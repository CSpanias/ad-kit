import io
from contextlib import nullcontext

from rich.console import Console

from ad_kit.checks import smb
from ad_kit.commands.checks import unauthenticated
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.reporting import results


def _share_output(rows):
    prefix = "SMB host 445 HOST "
    lines = [
        prefix + "Enumerated shares",
        prefix + f"{'Share':<15} {'Permissions':<22} Remark",
        prefix + f"{'-----':<15} {'-----------':<22} ------",
    ]
    lines.extend(
        prefix + f"{name:<15} {permissions:<22} {remark}"
        for name, permissions, remark in rows
    )
    return "\n".join(lines)


def test_share_access_combines_read_and_write_without_losing_names(monkeypatch):
    calls = []

    def run(name, command, sensitive_values):
        calls.append((name, command, sensitive_values))
        if command[command.index("--shares") + 1] == "READ":
            return _share_output([
                ("Compressor In", "READ", "A remark"),
                ("Compressor Out", "READ,WRITE", "Output"),
                ("Long READ share name", "READ,WRITE (ACL)", ""),
            ])
        return _share_output([
            ("Compressor Out", "READ,WRITE", "Output"),
            ("Long READ share name", "READ,WRITE (ACL)", ""),
            ("[Write Only]", "WRITE (SUBDIR)", ""),
        ])

    monkeypatch.setattr(smb, "run_check", run)
    shares, complete = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert complete
    assert shares == [
        {"name": "Compressor In", "permissions": ("READ",)},
        {"name": "Compressor Out", "permissions": ("READ", "WRITE")},
        {"name": "Long READ share name", "permissions": ("READ", "WRITE (ACL)")},
        {"name": "[Write Only]", "permissions": ("WRITE (SUBDIR)",)},
    ]
    assert [command[command.index("--shares") + 1] for _, command, _ in calls] == [
        "READ", "WRITE"
    ]
    assert all(secrets == ["secret"] for _, _, secrets in calls)


def test_share_access_preserves_read_results_when_write_check_fails(monkeypatch):
    results.reset()

    def run(name, command, sensitive_values):
        if command[command.index("--shares") + 1] == "WRITE":
            raise CheckExecutionError(name, [], returncode=1)
        return _share_output([("Read Only", "READ", "")])

    monkeypatch.setattr(smb, "run_check", run)
    shares, complete = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert shares == [{"name": "Read Only", "permissions": ("READ",)}]
    assert not complete
    assert any("SMB share access - host" in entry for entry in results._incomplete)
    results.reset()


def test_share_access_records_unparseable_and_failed_output(monkeypatch):
    results.reset()

    def run(name, command, sensitive_values):
        if command[command.index("--shares") + 1] == "READ":
            return _share_output([("share", "UNEXPECTED", "")])
        return "SMB host 445 HOST [-] Error enumerating shares"

    monkeypatch.setattr(smb, "run_check", run)
    shares, complete = smb.smb_share_access_check("host", "dc", "user", "secret")
    assert shares == []
    assert not complete
    assert any("Could not parse a READ" in entry for entry in results._incomplete)
    assert any("No complete WRITE" in entry for entry in results._incomplete)
    results.reset()


def test_share_table_and_finding_only_include_write_related_permissions(monkeypatch, tmp_path):
    results.reset()
    output = io.StringIO()
    monkeypatch.setattr(unauthenticated, "console", Console(file=output, width=160))
    monkeypatch.setattr(unauthenticated, "print_section", lambda title: print(title, file=output))
    monkeypatch.setattr(unauthenticated, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(unauthenticated, "track_items", lambda items, _label: items)
    monkeypatch.setattr(unauthenticated, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain_computers_exported": True,
    })
    monkeypatch.setattr(unauthenticated, "load_domain_computers", lambda: ["host"])
    monkeypatch.setattr(unauthenticated, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(unauthenticated, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(unauthenticated, "smb_configuration_check", lambda *_args, **_kwargs: {
        "host": "host", "signing": "[green]✓ Enabled[/green]", "smbv1": "[green]✓ Disabled[/green]",
        "null_auth": False, "anonymous_shares": None, "anonymous_users": None,
    })
    monkeypatch.setattr(unauthenticated, "smb_share_access_check", lambda *_args: ([
        {"name": "Read Only", "permissions": ("READ",)},
        {"name": "Writable", "permissions": ("READ", "WRITE")},
    ], True))

    unauthenticated.run_smb_checks("secret")
    table = output.getvalue().split("SMB Checks - Share Access", 1)[1]
    assert "Share" in table and "Permissions" in table
    assert any("Read Only" in line and "READ" in line for line in table.splitlines())
    assert any("Writable" in line and "READ, WRITE" in line for line in table.splitlines())
    finding = next(finding for finding in results._findings if finding.id == "SMB-004")
    assert len(finding.evidence) == 1
    assert "Writable" in finding.evidence[0]
    assert "Read Only" not in finding.evidence[0]
    results.reset()
