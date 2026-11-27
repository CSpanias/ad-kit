"""
SMB-related assessment checks.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import run_check
from ad_kit.core.exceptions import CheckExecutionError


class ShareAccess(TypedDict):
    name: str
    permissions: tuple[str, ...]


_SHARE_PERMISSION = r"(?:READ|WRITE(?: \((?:ACL|SUBDIR)\))?|UNKNOWN(?: \([^)]*\))?)"
_SHARE_PERMISSIONS = re.compile(
    rf"(?<!\S)(?P<permissions>{_SHARE_PERMISSION}(?:,{_SHARE_PERMISSION})*)(?=\s|$)"
)


def _smb_log_payload(line: str, *, keep_padding: bool = False) -> str | None:
    line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
    match = re.match(
        r"^\s*SMB\s+\S+\s+\d+\s+\S+\s+(.*)$",
        line,
        re.IGNORECASE,
    )
    if not match:
        return None
    return match.group(1) if keep_padding else match.group(1).strip()


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

        row = _smb_log_payload(line, keep_padding=True)
        if row is None:
            continue

        if not table_header_seen:
            if all(
                column in row.lower()
                for column in ("share", "permissions", "remark")
            ):
                table_header_seen = True
            continue

        if not row.strip() or re.fullmatch(r"[-\s]+", row):
            continue

        row_lower = row.lower().strip()
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


def _share_column_widths(output: str) -> tuple[int, int] | None:
    for line in output.splitlines():
        row = _smb_log_payload(line, keep_padding=True)
        if row is None:
            continue
        header = re.match(
            r"^Share\s+Permissions\s+(?:(?P<type>Type)\s+)?(?P<remark>Remark)(?:\s|$)",
            row,
            re.I,
        )
        if header is None:
            continue
        permission_start = row.lower().index("permissions")
        next_start = header.start("type" if header.group("type") else "remark")
        return permission_start - 1, next_start - permission_start - 1
    return None


def _parse_share_count(output: str) -> int | None:
    """Count shares in NetExec's share list or enumerated table output."""

    share_list_count = len(
        re.findall(
            r"""['"]shi1_netname['"]\s*:""",
            output,
            re.IGNORECASE,
        )
    )
    share_row_count = len(_parse_share_rows(output))
    if share_list_count or share_row_count:
        return max(share_list_count, share_row_count)
    if re.search(r"error enumerating shares", output, re.IGNORECASE):
        return None
    if re.search(r"shares returned:\s*\[\s*\]", output, re.IGNORECASE):
        return 0
    if _has_share_table(output):
        return 0
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


def _parse_empty_credential_login(output: str) -> tuple[bool | None, bool]:
    for line in output.splitlines():
        payload = _smb_log_payload(line)
        if payload is None:
            continue
        if re.match(r"^\[\+\]\s+\S*\\:\S*(?:\s|$)", payload):
            guest = bool(re.search(r"\(guest\)", payload, re.IGNORECASE))
            return (None if guest else True), guest
        if re.match(
            r"^\[-\]\s+\S*\\:\S*\s+STATUS_"
            r"(?:LOGON_FAILURE|ACCESS_DENIED|ACCOUNT_RESTRICTION|NO_SUCH_USER|"
            r"ACCOUNT_DISABLED|ACCOUNT_LOCKED_OUT|LOGON_TYPE_NOT_GRANTED)\b",
            payload,
            re.IGNORECASE,
        ):
            return False, False
    return None, False


def smb_share_access_check(
    host: str,
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[list[ShareAccess], list[str]]:
    """Return NetExec-reported share access without writing to shares."""

    evidence_name = f"smb-share-access-{host}"
    try:
        output = run_check(
            evidence_name,
            [
                "nxc", "smb", host,
                "-u", username,
                "-p", password,
                "--shares",
                "--dns-server", dc_ip,
            ],
            sensitive_values=[password],
            show_progress=False,
        )
    except CheckExecutionError as exc:
        return [], [str(exc)]

    if not _has_share_table(output):
        return [], [f"No complete share listing; see {evidence_name}.txt"]
    widths = _share_column_widths(output)
    if widths is None:
        return [], [f"Unrecognised share table format; see {evidence_name}.txt"]
    name_width, permission_width = widths

    shares: dict[str, ShareAccess] = {}
    errors = []
    table_output = re.split(r"enumerated shares", output, maxsplit=1, flags=re.I)[1]
    if "[-]" in table_output:
        errors.append(f"Share enumeration reported an error; see {evidence_name}.txt")
    for row in _parse_share_rows(output):
        if re.match(rf"^.{{{name_width},}}? {{{permission_width + 1}}}", row):
            continue
        candidates: list[tuple[str, tuple[str, ...]]] = []
        for match in _SHARE_PERMISSIONS.finditer(row):
            permissions = match.group("permissions")
            before = row[:match.start()]
            if match.start() < name_width + 1 or not before.endswith(" "):
                continue
            name = before.rstrip()
            if not name or (len(name) < name_width and match.start() != name_width + 1):
                continue
            if len(name) >= name_width and before.endswith("  "):
                continue
            padding = max(0, permission_width - len(permissions))
            after = row[match.end():]
            if len(after) < padding or after[:padding] != " " * padding:
                continue
            if len(after) > padding and after[padding] != " ":
                continue
            reported = tuple(permissions.split(","))
            candidates.append((name, reported))
        if len(candidates) != 1:
            errors.append(f"Could not parse a share result; see {evidence_name}.txt")
            continue
        name, reported = candidates[0]
        if any(item.startswith("UNKNOWN") for item in reported):
            errors.append(f"Unknown share permissions; see {evidence_name}.txt")
            continue
        shares[name.casefold()] = {"name": name, "permissions": reported}
    return list(shares.values()), errors


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
        ["nxc", "smb", host, "-u", "", "-p", "", "--dns-server", dc_ip],
        show_progress=False,
    )

    signing = "[yellow]⚠ Unknown[/yellow]"
    smbv1 = "[yellow]⚠ Unknown[/yellow]"
    null_auth, guest_auth = _parse_empty_credential_login(output)

    for line in output.splitlines():

        line = line.lower()

        signing_match = re.search(r"signing:([^)]*)", line)
        smbv1_match = re.search(r"smbv1:([^)]*)", line)

        if signing_match and signing_match.group(1).strip() in {"true", "false"}:
            signing = signing_match.group(1).strip()

        if smbv1_match and smbv1_match.group(1).strip() in {"true", "false", "none"}:
            smbv1 = smbv1_match.group(1).strip()

    anonymous_shares: int | None = None
    anonymous_users: int | None = None
    anonymous_users_complete = False
    incomplete: list[str] = []
    if null_auth or guest_auth:
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
                show_progress=False,
            )
        except CheckExecutionError as exc:
            incomplete.append(str(exc))
        else:
            anonymous_shares = _parse_share_count(enumeration_output)
            if anonymous_shares is None and re.search(
                r"error enumerating shares:\s*(?:STATUS_)?ACCESS_DENIED\b",
                enumeration_output,
                re.IGNORECASE,
            ):
                anonymous_shares = 0
                share_denied = True
            else:
                share_denied = False
            if share_denied and any(
                (payload := _smb_log_payload(line)) is not None
                and payload.startswith("[-]")
                and not re.search(
                    r"error enumerating shares:\s*(?:STATUS_)?ACCESS_DENIED\b",
                    payload,
                    re.IGNORECASE,
                )
                for line in enumeration_output.splitlines()
            ):
                incomplete.append("Anonymous enumeration reported an error; see evidence")
            if anonymous_shares is not None and re.search(
                r"error enumerating shares", enumeration_output, re.IGNORECASE
            ) and not share_denied:
                incomplete.append("Share enumeration reported an error; see evidence")
            if enumerate_users:
                anonymous_users, anonymous_users_complete = _parse_user_count(
                    enumeration_output
                )
                if (
                    anonymous_users is None
                    and not anonymous_users_complete
                    and not re.search(
                        r"error enumerating domain user", enumeration_output, re.IGNORECASE
                    )
                ):
                    try:
                        user_output = run_check(
                            f"smb-anonymous-users-{host}",
                            [
                                "nxc", "smb", host, "-u", "", "-p", "",
                                "--users", "--dns-server", dc_ip,
                            ],
                            show_progress=False,
                        )
                    except CheckExecutionError as exc:
                        incomplete.append(str(exc))
                    else:
                        anonymous_users, anonymous_users_complete = _parse_user_count(
                            user_output
                        )
                        user_null_auth, user_guest_auth = _parse_empty_credential_login(
                            user_output
                        )
                        if (
                            anonymous_users is None
                            and not anonymous_users_complete
                            and (user_null_auth or user_guest_auth)
                            and not re.search(r"\[-\]", user_output)
                        ):
                            anonymous_users = 0
                            anonymous_users_complete = True
            missing = []
            if anonymous_shares is None:
                missing.append("share enumeration")
            if enumerate_users and not anonymous_users_complete:
                missing.append("user enumeration")
            if missing:
                incomplete.append(
                    f"No complete result for {' and '.join(missing)}; see evidence"
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
        "guest_auth": guest_auth,
        "anonymous_shares": anonymous_shares,
        "anonymous_users": anonymous_users,
        "anonymous_users_complete": anonymous_users_complete,
        "anonymous_incomplete": incomplete,
    }
