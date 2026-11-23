"""
SMB-related assessment checks.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import run_check
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.reporting.results import record_incomplete


class ShareAccess(TypedDict):
    name: str
    permissions: tuple[str, ...]


_SHARE_PERMISSION = r"(?:READ|WRITE(?: \((?:ACL|SUBDIR)\))?|UNKNOWN(?: \([^)]*\))?)"
_SHARE_PERMISSIONS = re.compile(
    rf"(?<!\S)(?P<permissions>{_SHARE_PERMISSION}(?:,{_SHARE_PERMISSION})*)(?=\s|$)"
)


def _smb_log_payload(line: str) -> str | None:
    line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
    match = re.match(
        r"^\s*SMB\s+\S+\s+\d+\s+\S+\s+(.*)$",
        line,
        re.IGNORECASE,
    )
    return match.group(1).strip() if match else None


def _is_user_table_header(row: str) -> bool:
    row_lower = row.lower()
    return "username" in row_lower and "last pw set" in row_lower


def _parse_share_rows(output: str) -> list[str]:
    shares = []
    in_share_table = False
    table_header_seen = False

    for line in output.splitlines():
        if "enumerated shares" in line.lower():
            in_share_table = True
            continue

        if not in_share_table:
            continue

        row = _smb_log_payload(line)
        if row is None:
            continue

        if not table_header_seen:
            if all(
                column in row.lower()
                for column in ("share", "permissions", "remark")
            ):
                table_header_seen = True
            continue

        if not row or re.fullmatch(r"[-\s]+", row):
            continue

        row_lower = row.lower()
        if (
            _is_user_table_header(row)
            or row.startswith(("[+]", "[-]", "[*]", "[!]"))
            or row_lower.startswith("enumerated ")
        ):
            break

        shares.append(row)

    return shares


def _has_share_table(output: str) -> bool:
    return bool(re.search(r"enumerated shares", output, re.IGNORECASE)) and any(
        all(column in row.lower() for column in ("share", "permissions", "remark"))
        for line in output.splitlines()
        if (row := _smb_log_payload(line)) is not None
    )


def _parse_share_count(output: str) -> int | None:
    """Count shares in NetExec's share list or enumerated table output."""

    share_list_count = len(
        re.findall(
            r"""['"]shi1_netname['"]\s*:""",
            output,
            re.IGNORECASE,
        )
    )
    if share_list_count:
        return max(share_list_count, len(_parse_share_rows(output)))
    if re.search(r"shares returned:\s*\[\s*\]", output, re.IGNORECASE):
        return 0
    if _has_share_table(output):
        return len(_parse_share_rows(output))
    return None


def _parse_user_count(output: str) -> tuple[int | None, bool]:
    user_count = 0
    user_table_seen = False

    for line in output.splitlines():
        row = _smb_log_payload(line)
        if row is None:
            continue

        row_lower = row.lower()
        if _is_user_table_header(row):
            user_table_seen = True
            continue

        if not user_table_seen:
            continue

        if not row or re.fullmatch(r"[-\s]+", row):
            continue

        if row.startswith("[") or row_lower.startswith("enumerated "):
            break

        user_count += 1

    # NetExec may report only the last page's count when enumeration is paged.
    users_match = re.search(
        r"Enumerated\s+(\d+)\s+local users:",
        output,
        re.IGNORECASE,
    )
    complete = users_match is not None and not re.search(
        r"error enumerating domain user", output, re.IGNORECASE
    )
    if complete and users_match is not None:
        return max(user_count, int(users_match.group(1))), True
    return (user_count if user_count else None), False


def smb_share_access_check(
    host: str,
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[list[ShareAccess], bool]:
    """Return NetExec-reported share access without writing to shares."""

    shares: dict[str, ShareAccess] = {}
    complete = True
    for access, label in (("READ", "readable"), ("WRITE", "writable")):
        evidence_name = f"smb-{label}-shares-{host}"
        try:
            output = run_check(
                evidence_name,
                [
                    "nxc", "smb", host,
                    "-u", username,
                    "-p", password,
                    "--shares", access,
                    "--dns-server", dc_ip,
                ],
                sensitive_values=[password],
            )
        except CheckExecutionError as exc:
            record_incomplete("SMB share access", host, str(exc), notify=False)
            complete = False
            continue

        if not _has_share_table(output):
            record_incomplete(
                "SMB share access", host,
                f"No complete {access} share listing; see {evidence_name}.txt",
                notify=False,
            )
            complete = False
            continue

        for row in _parse_share_rows(output):
            for match in _SHARE_PERMISSIONS.finditer(row):
                permissions = match.group("permissions")
                end = match.end("permissions")
                if match.start("permissions") < 16:
                    continue
                if len(permissions) < 22 and end < len(row) and row[end:end + 2] != "  ":
                    continue
                name = row[:match.start("permissions")].rstrip()
                reported = tuple(permissions.split(","))
                if not name or not any(item.startswith(access) for item in reported):
                    continue
                previous = shares.get(name.casefold())
                combined = tuple(dict.fromkeys(
                    (previous["permissions"] if previous else ()) + reported
                ))
                shares[name.casefold()] = {"name": name, "permissions": combined}
                break
            else:
                record_incomplete(
                    "SMB share access", host,
                    f"Could not parse a {access} share result; see {evidence_name}.txt",
                    notify=False,
                )
                complete = False
    return list(shares.values()), complete


def smb_configuration_check(
    host: str,
    dc_ip: str,
    *,
    enumerate_users: bool = False,
) -> dict:
    """
    Check SMB configuration and anonymous enumeration on a target host.

    Name resolution is performed using the specified
    Domain Controller DNS service to ensure that
    domain hosts can be resolved even when the local
    system is not configured to use Active Directory
    DNS.

    Args:
        host: Target hostname or FQDN.
        dc_ip: Domain Controller IP address to use
            for DNS resolution.
        enumerate_users: Whether to enumerate accounts on a Domain Controller.

    Returns:
        Dictionary containing SMB configuration
        results.
    """

    output = run_check(
        f"smb-{host}",
        ["nxc", "smb", host, "--dns-server", dc_ip],
    )

    signing = "[yellow]⚠ Unknown[/yellow]"
    smbv1 = "[yellow]⚠ Unknown[/yellow]"
    null_auth: bool | None = None
    host_info_seen = False

    for line in output.splitlines():

        line = line.lower()

        signing_match = re.search(r"signing:([^)]*)", line)
        smbv1_match = re.search(r"smbv1:([^)]*)", line)

        if signing_match:
            signing = signing_match.group(1).strip()

        if smbv1_match:
            smbv1 = smbv1_match.group(1).strip()

        if signing_match or smbv1_match:
            host_info_seen = True

        null_auth_match = re.search(r"null auth:([^)]*)", line)
        if null_auth_match:
            null_auth_value = null_auth_match.group(1).strip()

            if null_auth_value == "true":
                null_auth = True
            elif null_auth_value == "false":
                null_auth = False

    if null_auth is None and host_info_seen:
        null_auth = False

    anonymous_shares: int | None = None
    anonymous_users: int | None = None
    anonymous_users_complete = False
    if null_auth:
        command = [
            "nxc", "smb", host,
            "-u", "",
            "-p", "",
            "--shares",
        ]
        if enumerate_users:
            command.append("--users")
        command.extend(["--dns-server", dc_ip])
        try:
            enumeration_output = run_check(
                f"smb-anonymous-enumeration-{host}",
                command,
            )
        except CheckExecutionError as exc:
            record_incomplete("SMB anonymous enumeration", host, str(exc), notify=False)
        else:
            anonymous_shares = _parse_share_count(enumeration_output)
            if enumerate_users:
                anonymous_users, anonymous_users_complete = _parse_user_count(
                    enumeration_output
                )
            incomplete = []
            if anonymous_shares is None:
                incomplete.append("share enumeration")
            if enumerate_users and not anonymous_users_complete:
                incomplete.append("user enumeration")
            if incomplete:
                record_incomplete(
                    "SMB anonymous enumeration",
                    host,
                    f"No complete result for {' and '.join(incomplete)}; see evidence",
                    notify=False,
                )

    if signing == "true":
        signing = "[green]✓ Enabled[/green]"

    elif signing == "false":
        signing = "[red]✗ Disabled[/red]"

    if smbv1 == "none":
        smbv1 = "[green]✓ Disabled[/green]"

    elif smbv1 == "false":
        smbv1 = "[green]✓ Disabled[/green]"

    elif smbv1 == "true":
        smbv1 = "[red]✗ Enabled[/red]"

    return {
        "host": host,
        "signing": signing,
        "smbv1": smbv1,
        "null_auth": null_auth,
        "anonymous_shares": anonymous_shares,
        "anonymous_users": anonymous_users,
        "anonymous_users_complete": anonymous_users_complete,
    }
