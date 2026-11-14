"""
SMB-related assessment checks.
"""

import re

from ad_kit.core.checks import run_check


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
        anonymous_shares = len(
            re.findall(
                r"""['"]shi1_netname['"]\s*:""",
                enumeration_output,
                re.IGNORECASE,
            )
        )
        users_match = re.search(
            r"Enumerated\s+(\d+)\s+local users:",
            enumeration_output,
            re.IGNORECASE,
        )
        if users_match:
            anonymous_users = int(users_match.group(1))

    if signing == "true":
        signing = "[green]✓ Enabled[/green]"

    elif signing == "false":
        signing = "[red]✗ Disabled[/red]"

    if smbv1 == "none":
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
