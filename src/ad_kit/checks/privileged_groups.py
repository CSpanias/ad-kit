"""
Privileged group assessment checks.

This module implements checks relating to privileged
Active Directory group membership.

Checks implemented within this module are intended
to identify situations where a disproportionate
number of enabled user accounts hold elevated
administrative privileges.
"""

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


PRIVILEGED_GROUPS = (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "DNSAdmins",
)


def privileged_groups_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Assess membership of privileged Active Directory groups.

    The check retrieves membership of selected privileged groups and compares 
    membership counts against the number of enabled user accounts in the domain.

    Findings are generated where privileged group membership exceeds the 
    configured assessment threshold.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing:

        - Parsed privileged group results.
        - Generated findings.
    """

    results = {
        "enabled_users": 0,
        "groups": {},
    }

    findings: list[Finding] = []

    # Enabled users
    users_output = run_check(
        "privileged-users",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "--users",
        ],
    )

    enabled_users = 0

    for line in users_output.splitlines():

        if (
            "[+]" in line
            or "[*]" in line
            or not line.strip()
        ):
            continue

        enabled_users += 1

    results["enabled_users"] = enabled_users

    # Privileged groups
    for group in PRIVILEGED_GROUPS:

        output = run_check(
            f"privileged-{group.lower().replace(' ', '-')}",
            [
                "nxc",
                "ldap",
                dc_ip,
                "-u",
                username,
                "-p",
                password,
                "--groups",
                group,
            ],
        )

        members = []

        for line in output.splitlines():

            if (
                "[+]" in line
                or "[*]" in line
                or not line.strip()
            ):
                continue

            member = line.split()[-1].strip()

            if member:

                members.append(member)

        member_count = len(members)

        percentage = (
            round((member_count / enabled_users) * 100, 1)
            if enabled_users
            else 0
        )

        results["groups"][group] = {
            "member_count": member_count,
            "percentage": percentage,
            "members": sorted(members),
        }

        # Assessment threshold
        if percentage >= 10.0:

            finding = load_finding("privileged_groups", "PRIV-001")

            finding.evidence.append(
                f"The domain contained {enabled_users} enabled user accounts."
            )

            finding.evidence.append(
                f"The '{group}' group contained {member_count} member(s)."
            )

            finding.evidence.append(
                f"'{group}' represented {percentage}% of the enabled user "
                "population."
            )

            findings.append(finding)

    return results, findings