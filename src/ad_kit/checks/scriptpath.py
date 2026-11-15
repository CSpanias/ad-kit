"""
User logon script path and permission assessment.
"""

import re
from pathlib import PureWindowsPath
from typing import Literal, TypedDict

from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.smb import (
    FILE_APPEND_DATA,
    FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_WRITE_DATA,
    READ_CONTROL,
)
from impacket.smb3structs import (
    DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION,
    SMB2_0_INFO_SECURITY,
)
from impacket.smbconnection import SessionError, SMBConnection

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding

SCRIPT_PATH_PATTERN = re.compile(
    r"\bUser:\s*(\S+)\s+ScriptPath:\s*(.*?)\s*$",
    re.IGNORECASE,
)
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
MISSING_PATH_STATUSES = {
    STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND,
}

WRITE_RIGHTS = (
    (0x10000000, "GENERIC_ALL"),
    (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x00000001, "READ_DATA / LIST_DIRECTORY"),
    (0x00000002, "WRITE_DATA / ADD_FILE"),
    (0x00000004, "APPEND_DATA / ADD_SUBDIRECTORY"),
    (0x00000008, "READ_EA"),
    (0x00000010, "WRITE_EA"),
    (0x00000020, "EXECUTE / TRAVERSE"),
    (0x00000080, "READ_ATTRIBUTES"),
    (0x00000100, "WRITE_ATTRIBUTES"),
    (0x00000040, "DELETE_CHILD"),
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00100000, "SYNCHRONIZE"),
)
ALLOW_ACE_TYPES = {0, 5, 9, 11}
DENY_ACE_TYPES = {1, 6, 10, 12}


class ScriptPathEntry(TypedDict):
    username: str
    script_path: str
    resolved_path: str
    acl_entries: list[str]
    standard_user_writable: Literal["Yes", "No", "Unknown"]
    error: str | None


class _PathPermission(TypedDict):
    acl_entries: list[str]
    standard_user_writable: Literal["Yes", "No", "Unknown"]
    error: str | None


def _parse_script_paths(output: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for line in output.splitlines():
        match = SCRIPT_PATH_PATTERN.search(line)
        if match is None:
            continue

        username, script_path = match.groups()
        script_path = script_path.strip()
        key = (username.casefold(), script_path.casefold())

        if script_path and key not in seen:
            entries.append((username, script_path))
            seen.add(key)

    return entries


def _allowed_smb_hosts(
    domain: str,
    dc_ips: list[str],
    dc_hostnames: list[str],
) -> set[str]:
    hosts = {domain.casefold().rstrip(".")}
    hosts.update(ip.casefold() for ip in dc_ips)

    for hostname in dc_hostnames:
        normalized = hostname.casefold().rstrip(".")
        hosts.add(normalized)
        hosts.add(normalized.split(".", 1)[0])

    return hosts


def _resolve_script_path(
    script_path: str,
    dc_ip: str,
    domain: str,
    allowed_hosts: set[str],
) -> tuple[str, str, str] | None:
    normalized_path = script_path.strip().replace("/", "\\")

    if normalized_path.startswith("\\\\"):
        parts = [
            part
            for part in normalized_path[2:].split("\\")
            if part
        ]
        if len(parts) < 2:
            return None

        server, share, *path_parts = parts
        if server.casefold().rstrip(".") not in allowed_hosts:
            return None

        if ".." in path_parts:
            return None

        target = (
            dc_ip
            if server.casefold().rstrip(".") == domain.casefold().rstrip(".")
            else server
        )
        return target, share, "\\".join(path_parts)

    windows_path = PureWindowsPath(normalized_path)
    if windows_path.drive or ".." in windows_path.parts:
        return None

    relative_path = "\\".join(
        part
        for part in windows_path.parts
        if part not in {"\\", "."}
    )
    if not relative_path:
        return None

    return dc_ip, "NETLOGON", relative_path


def _format_security_descriptor(
    raw_descriptor: bytes,
) -> list[str]:
    descriptor = SR_SECURITY_DESCRIPTOR(data=raw_descriptor)
    entries: list[str] = []

    owner_sid = descriptor["OwnerSid"]
    if owner_sid not in (None, b""):
        entries.append(f"Owner: {owner_sid.formatCanonical()}")

    group_sid = descriptor["GroupSid"]
    if group_sid not in (None, b""):
        entries.append(f"Group: {group_sid.formatCanonical()}")

    dacl = descriptor["Dacl"]
    if dacl in (None, b""):
        entries.append("NULL DACL (unrestricted)")
        return entries

    if not dacl.aces:
        entries.append("Empty DACL")
        return entries

    for ace in dacl.aces:
        ace_type = int(ace["AceType"])
        ace_flags = int(ace["AceFlags"])
        ace_data = ace["Ace"]

        try:
            trustee = ace_data["Sid"].formatCanonical()
            mask = int(ace_data["Mask"]["Mask"])
        except (AttributeError, KeyError, TypeError):
            entries.append(f"ACE type 0x{ace_type:02X}: unable to decode")
            continue

        if ace_type in ALLOW_ACE_TYPES:
            action = "ALLOW"
        elif ace_type in DENY_ACE_TYPES:
            action = "DENY"
        else:
            action = f"ACE 0x{ace_type:02X}"

        rights = [
            name
            for bit, name in WRITE_RIGHTS
            if mask & bit
        ]
        rights_text = ", ".join(rights) if rights else f"mask=0x{mask:08X}"
        inherited = " (inherited)" if ace_flags & 0x10 else ""
        entries.append(
            f"{action} {trustee}: {rights_text}{inherited}"
        )

    return entries


def _read_file_acl(
    connection: SMBConnection,
    tree_id: int,
    path: str,
) -> list[str]:
    handle = connection.openFile(
        tree_id,
        path,
        desiredAccess=READ_CONTROL,
        shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        creationOption=FILE_NON_DIRECTORY_FILE,
        creationDisposition=FILE_OPEN,
    )

    try:
        raw_descriptor = connection.getSMBServer().queryInfo(
            tree_id,
            handle,
            infoType=SMB2_0_INFO_SECURITY,
            additionalInformation=(
                OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
            ),
        )
        return _format_security_descriptor(raw_descriptor)
    finally:
        connection.closeFile(tree_id, handle)


def _probe_write_access(
    connection: SMBConnection,
    tree_id: int,
    path: str,
) -> tuple[Literal["Yes", "No", "Unknown"], str | None]:
    denied_count = 0

    for desired_access in (FILE_WRITE_DATA, FILE_APPEND_DATA):
        try:
            handle = connection.openFile(
                tree_id,
                path,
                desiredAccess=desired_access,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                creationOption=FILE_NON_DIRECTORY_FILE,
                creationDisposition=FILE_OPEN,
            )
        except SessionError as error:
            error_code = error.getErrorCode()
            if error_code == STATUS_ACCESS_DENIED:
                denied_count += 1
                continue
            if error_code in MISSING_PATH_STATUSES:
                return (
                    "Unknown",
                    f"Script file not found on the queried SMB share "
                    f"(NTSTATUS 0x{error_code:08X}).",
                )
            return (
                "Unknown",
                f"SMB write-access probe failed (NTSTATUS "
                f"0x{error_code:08X}).",
            )

        try:
            connection.closeFile(tree_id, handle)
        except SessionError as error:
            return (
                "Yes",
                f"Write access was granted, but closing the SMB handle failed "
                f"(NTSTATUS 0x{error.getErrorCode():08X}).",
            )

        return "Yes", None

    return ("No", None) if denied_count == 2 else ("Unknown", None)


def _inspect_resolved_path(
    server: str,
    share: str,
    path: str,
    username: str,
    password: str,
    domain: str,
) -> _PathPermission:
    connection: SMBConnection | None = None
    tree_id: int | None = None
    acl_entries: list[str] = []
    writable: Literal["Yes", "No", "Unknown"] = "Unknown"
    errors: list[str] = []
    path_missing = False
    account = username
    account_domain = domain
    if "\\" in account:
        account_domain, account = account.split("\\", 1)
    elif "@" in account:
        account, account_domain = account.rsplit("@", 1)

    try:
        connection = SMBConnection(server, server, timeout=10)
        connection.login(account, password, account_domain)
        tree_id = connection.connectTree(share)

        try:
            acl_entries = _read_file_acl(connection, tree_id, path)
        except SessionError as error:
            error_code = error.getErrorCode()
            if error_code in MISSING_PATH_STATUSES:
                errors.append(
                    f"Script file not found on the queried SMB share "
                    f"(NTSTATUS 0x{error_code:08X})."
                )
                path_missing = True
            else:
                errors.append(
                    f"ACL query failed (NTSTATUS 0x{error_code:08X})."
                )

        if not path_missing:
            writable, probe_error = _probe_write_access(
                connection,
                tree_id,
                path,
            )
            if probe_error:
                errors.append(probe_error)
    except (OSError, SessionError) as error:
        errors.append(str(error))
    finally:
        if connection is not None:
            if tree_id is not None:
                try:
                    connection.disconnectTree(tree_id)
                except (OSError, SessionError) as error:
                    errors.append(f"SMB tree cleanup failed: {error}")
            try:
                connection.logoff()
            except (OSError, SessionError) as error:
                errors.append(f"SMB session cleanup failed: {error}")

    return {
        "acl_entries": acl_entries,
        "standard_user_writable": writable,
        "error": "; ".join(errors) if errors else None,
    }


def scriptpath_check(
    dc_ip: str,
    dc_ips: list[str],
    dc_hostnames: list[str],
    domain: str,
    username: str,
    password: str,
) -> tuple[list[ScriptPathEntry], list[Finding]]:
    """
    Enumerate user scriptPath values and inspect safe-to-query SMB paths.

    Relative paths are resolved against the primary DC's NETLOGON share.
    Explicit UNC paths are queried only when their server is a discovered
    Domain Controller or the configured domain name.
    """

    ldap_output = run_check(
        "get-scriptpath",
        [
            "nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
            "-M", "get-scriptpath",
        ],
        sensitive_values=[password],
    )
    script_paths = _parse_script_paths(ldap_output)
    allowed_hosts = _allowed_smb_hosts(domain, dc_ips, dc_hostnames)
    permission_cache: dict[tuple[str, str, str], _PathPermission] = {}
    results: list[ScriptPathEntry] = []

    for account, script_path in script_paths:
        resolved = _resolve_script_path(
            script_path,
            dc_ip,
            domain,
            allowed_hosts,
        )

        permission: _PathPermission
        if resolved is None:
            permission = {
                "acl_entries": [],
                "standard_user_writable": "Unknown",
                "error": (
                    "Path was not queried because it is unsupported or its "
                    "server is outside the discovered Domain Controller scope."
                ),
            }
            resolved_path = script_path
        else:
            server, share, relative_path = resolved
            cache_key = (
                server.casefold(),
                share.casefold(),
                relative_path.casefold(),
            )
            if cache_key not in permission_cache:
                permission_cache[cache_key] = _inspect_resolved_path(
                    server,
                    share,
                    relative_path,
                    username,
                    password,
                    domain,
                )
            permission = permission_cache[cache_key]
            resolved_path = f"\\\\{server}\\{share}\\{relative_path}"

        results.append(
            {
                "username": account,
                "script_path": script_path,
                "resolved_path": resolved_path,
                "acl_entries": permission["acl_entries"],
                "standard_user_writable": permission[
                    "standard_user_writable"
                ],
                "error": permission["error"],
            }
        )

    writable_results = [
        result
        for result in results
        if result["standard_user_writable"] == "Yes"
    ]
    findings: list[Finding] = []

    if writable_results:
        finding = load_finding("scriptpath", "SCRIPT-001")
        for result in writable_results:
            finding.affected_assets.append(result["resolved_path"])
            finding.evidence.append(
                f"Standard User '{username}' was granted write or append "
                f"access to the logon script '{result['resolved_path']}', "
                f"assigned to '{result['username']}'."
            )
        findings.append(finding)

    return results, findings
