"""
SMB-related assessment checks.
"""

import re

from ad_kit.core.checks import run_check


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
            or row.startswith("[")
            or row_lower.startswith("enumerated ")
        ):
            break

        shares.append(" ".join(row.split()))

    return shares


def _parse_share_count(output: str) -> int:
    """Count shares in NetExec's share list or enumerated table output."""

    share_list_count = len(
        re.findall(
            r"""['"]shi1_netname['"]\s*:""",
            output,
            re.IGNORECASE,
        )
    )
    return max(share_list_count, len(_parse_share_rows(output)))


def _parse_user_count(output: str) -> int:
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

    if user_table_seen:
        return user_count

    # NetExec may report only the last page's count when enumeration is paged.
    users_match = re.search(
        r"Enumerated\s+(\d+)\s+local users:",
        output,
        re.IGNORECASE,
    )
    return int(users_match.group(1)) if users_match else 0


def smb_writable_share_check(
    host: str,
    dc_ip: str,
    username: str,
    password: str,
) -> list[str]:
    """Return NetExec-reported writable shares without writing to them."""

    output = run_check(
        f"smb-writable-shares-{host}",
        [
            "nxc", "smb", host,
            "-u", username,
            "-p", password,
            "--shares", "WRITE",
            "--dns-server", dc_ip,
        ],
        sensitive_values=[password],
    )
    return _parse_share_rows(output)


def smb_configuration_check(
    host: str,
    dc_ip: str,
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
    if null_auth:
        anonymous_shares = 0
        anonymous_users = 0
        enumeration_output = run_check(
            f"smb-anonymous-enumeration-{host}",
            [
                "nxc", "smb", host,
                "-u", "",
                "-p", "",
                "--shares",
                "--users",
                "--dns-server", dc_ip,
            ],
        )
        anonymous_shares = _parse_share_count(enumeration_output)
        anonymous_users = _parse_user_count(enumeration_output)

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
    }
