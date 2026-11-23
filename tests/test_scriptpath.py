import io
import struct
from contextlib import nullcontext

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_MASK,
    ACE,
    ACL,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)
from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError
from rich.console import Console

from ad_kit.checks import scriptpath
from ad_kit.commands.checks import hosts


def test_scriptpath_check_reports_paths_and_writable_scripts(monkeypatch):
    commands = []

    def fake_run_check(name, command, sensitive_values):
        commands.append((name, command, sensitive_values))
        return (
            "GET-SCRI... 192.0.2.1 389 DC01 [+] User: OPAL_POPE "
            "ScriptPath: test.ps1"
        )

    monkeypatch.setattr(scriptpath, "run_check", fake_run_check)
    monkeypatch.setattr(
        scriptpath,
        "_inspect_resolved_path",
        lambda *args: {
            "acl_entries": ["ALLOW S-1-5-21-1-2-3-1000: WRITE_DATA"],
            "standard_user_writable": "Yes",
            "error": None,
        },
    )

    results, findings = scriptpath.scriptpath_check(
        "192.0.2.1",
        ["192.0.2.1"],
        ["DC01.example.test"],
        "example.test",
        "poppy",
        "Password123!",
    )

    assert results[0]["resolved_path"] == (
        "\\\\192.0.2.1\\NETLOGON\\test.ps1"
    )
    assert results[0]["standard_user_writable"] == "Yes"
    assert [finding.id for finding in findings] == ["SCRIPT-001"]
    assert commands[0][1] == [
        "nxc",
        "ldap",
        "192.0.2.1",
        "-u",
        "poppy",
        "-p",
        "Password123!",
        "-M",
        "get-scriptpath",
    ]
    assert commands[0][2] == ["Password123!"]


def test_scriptpath_resolution_rejects_untrusted_unc_and_traversal():
    allowed_hosts = scriptpath._allowed_smb_hosts(
        "example.test",
        ["192.0.2.1"],
        ["DC01.example.test"],
    )

    assert scriptpath._resolve_script_path(
        "test.ps1",
        "192.0.2.1",
        "example.test",
        allowed_hosts,
    ) == ("192.0.2.1", "NETLOGON", "test.ps1")
    assert scriptpath._resolve_script_path(
        r"\\outside.example\share\test.ps1",
        "192.0.2.1",
        "example.test",
        allowed_hosts,
    ) is None
    assert scriptpath._resolve_script_path(
        r"..\outside.ps1",
        "192.0.2.1",
        "example.test",
        allowed_hosts,
    ) is None
    assert scriptpath._resolve_script_path(
        r"\\example.test\NETLOGON\test.ps1",
        "192.0.2.1",
        "example.test",
        allowed_hosts,
    ) == ("192.0.2.1", "NETLOGON", "test.ps1")


def test_write_access_probe_opens_then_closes_without_writing():
    class FakeConnection:
        def __init__(self):
            self.opened_access = []
            self.closed = []

        def openFile(self, tree_id, path, **kwargs):
            self.opened_access.append(kwargs["desiredAccess"])
            return b"handle"

        def closeFile(self, tree_id, handle):
            self.closed.append(handle)

        def writeFile(self, *args, **kwargs):
            raise AssertionError("The permission probe must not write.")

    connection = FakeConnection()
    result = scriptpath._probe_write_access(
        connection,
        1,
        "test.ps1",
    )

    assert result == ("Yes", None)
    assert connection.opened_access == [scriptpath.FILE_WRITE_DATA]
    assert connection.closed == [b"handle"]


def test_missing_script_file_is_reported_without_crashing(monkeypatch):
    class MissingFileConnection:
        def __init__(self):
            self.open_count = 0

        def login(self, username, password, domain):
            pass

        def connectTree(self, share):
            return 1

        def openFile(self, *args, **kwargs):
            self.open_count += 1
            raise SessionError(scriptpath.STATUS_OBJECT_NAME_NOT_FOUND)

        def disconnectTree(self, tree_id):
            pass

        def logoff(self):
            pass

    connection = MissingFileConnection()
    monkeypatch.setattr(
        scriptpath,
        "SMBConnection",
        lambda *args, **kwargs: connection,
    )

    result = scriptpath._inspect_resolved_path(
        "192.0.2.1",
        "NETLOGON",
        "missing.ps1",
        "poppy",
        "password",
        "example.test",
    )

    assert result["standard_user_writable"] == "Unknown"
    assert "not found" in result["error"]
    assert connection.open_count == 1


def test_acl_query_uses_security_information_class_and_closes_handle(monkeypatch):
    class Connection:
        def __init__(self):
            self.closed = []
            self.query = None

        def openFile(self, *args, **kwargs):
            return b"handle"

        def getDialect(self):
            return 0x0311

        def getSMBServer(self):
            return self

        def queryInfo(self, tree_id, handle, **kwargs):
            self.query = kwargs
            return b"descriptor"

        def closeFile(self, tree_id, handle):
            self.closed.append(handle)

    connection = Connection()
    monkeypatch.setattr(scriptpath, "_format_security_descriptor", lambda data: ["ACL"])
    assert scriptpath._read_file_acl(connection, 1, "test.ps1") == ["ACL"]
    assert connection.query["infoType"] == scriptpath.SMB2_0_INFO_SECURITY
    assert connection.query["fileInfoClass"] == 0
    assert connection.closed == [b"handle"]


def test_raw_smb3_acl_error_is_reported_and_write_probe_continues(monkeypatch):
    class Connection:
        def __init__(self):
            self.closed = []

        def login(self, *args):
            pass

        def connectTree(self, share):
            return 1

        def openFile(self, *args, **kwargs):
            return b"handle"

        def getDialect(self):
            return 0x0311

        def getSMBServer(self):
            return self

        def queryInfo(self, *args, **kwargs):
            raise SMB3SessionError(0xC000000D)

        def closeFile(self, tree_id, handle):
            self.closed.append(handle)

        def disconnectTree(self, tree_id):
            pass

        def logoff(self):
            pass

    connection = Connection()
    monkeypatch.setattr(scriptpath, "SMBConnection", lambda *args, **kwargs: connection)
    result = scriptpath._inspect_resolved_path(
        "dc", "NETLOGON", "test.ps1", "user", "password", "example.test"
    )
    assert result["standard_user_writable"] == "Yes"
    assert "ACL query failed (NTSTATUS 0xC000000D)" in result["error"]
    assert connection.closed == [b"handle", b"handle"]


def test_scriptpath_acl_failure_is_recorded_as_incomplete(monkeypatch, tmp_path):
    output = io.StringIO()
    monkeypatch.setattr(hosts, "console", Console(file=output, width=160))
    monkeypatch.setattr(hosts, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user", "domain": "example.test",
    })
    monkeypatch.setattr(hosts, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(hosts, "get_evidence_dir", lambda: tmp_path)
    monkeypatch.setattr(hosts, "scriptpath_check", lambda *_args: ([{
        "username": "alice",
        "script_path": "test.ps1",
        "resolved_path": r"\\dc\NETLOGON\test.ps1",
        "acl_entries": ["ALLOW S-1-5-21-1-2-3-1000: WRITE_DATA"],
        "standard_user_writable": "Yes",
        "error": "ACL query failed (NTSTATUS 0xC000000D).",
    }], []))
    incomplete = []
    monkeypatch.setattr(
        hosts, "record_incomplete",
        lambda check, path, reason, *, notify: incomplete.append((check, path, reason)),
    )
    hosts.run_scriptpath_checks("password")
    assert incomplete == [
        ("scriptPath", r"\\dc\NETLOGON\test.ps1", "ACL query failed (NTSTATUS 0xC000000D).")
    ]
    assert "ACL query failed" in output.getvalue()
    assert "WRITE_DATA" not in output.getvalue()
    assert "WRITE_DATA" in (tmp_path / "scriptpath-permissions.txt").read_text()


def test_security_descriptor_without_dacl_is_reported_as_unrestricted():
    descriptor = struct.pack(
        "<BBHLLLL",
        1,
        0,
        0x8004,
        0,
        0,
        0,
        0,
    )

    assert scriptpath._format_security_descriptor(descriptor) == [
        "NULL DACL (unrestricted)"
    ]


def test_security_descriptor_formats_inherited_write_ace():
    sid = LDAP_SID()
    sid.fromCanonical("S-1-5-21-1-2-3-1000")

    access_mask = ACCESS_MASK()
    access_mask["Mask"] = scriptpath.FILE_WRITE_DATA

    allowed_ace = ACCESS_ALLOWED_ACE()
    allowed_ace["Mask"] = access_mask
    allowed_ace["Sid"] = sid

    ace = ACE()
    ace["AceType"] = 0
    ace["AceFlags"] = 0x10
    ace["Ace"] = allowed_ace
    ace["AceSize"] = len(allowed_ace.getData()) + 4

    dacl = ACL()
    dacl["AclRevision"] = 2
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = [ace]

    descriptor = SR_SECURITY_DESCRIPTOR()
    descriptor["Revision"] = b"\x01"
    descriptor["Sbz1"] = b"\x00"
    descriptor["Control"] = 0x8004
    descriptor["Sacl"] = b""
    descriptor["Dacl"] = dacl
    descriptor["OwnerSid"] = b""
    descriptor["GroupSid"] = b""

    assert scriptpath._format_security_descriptor(descriptor.getData()) == [
        "ALLOW S-1-5-21-1-2-3-1000: WRITE_DATA / ADD_FILE (inherited)"
    ]
