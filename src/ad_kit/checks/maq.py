"""
Machine Account Quota assessment checks.
"""

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding


def maq_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Retrieve and assess the domain Machine Account Quota configuration.

    The check authenticates to Active Directory using the supplied credentials 
    and retrieves Machine Account Quota settings together with delegated 
    permissions that allow users to join devices to the domain.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing:

        - Parsed Machine Account Quota results for display.
        - Generated findings.
    """

    output = run_check(
        "maq",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "-M",
            "maq",
        ],
    )

    results = {
        "machine_account_quota": "Unknown",
        "machine_join_group": "Unknown",
    }

    findings: list[Finding] = []

    for line in output.splitlines():

        if "MachineAccountQuota:" in line:

            maq = int(line.split(":")[-1].strip())

            results["machine_account_quota"] = str(maq)

        elif "Authenticated Users" in line:

            results["machine_join_group"] = "Authenticated Users"

    return results, findings