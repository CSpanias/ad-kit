"""
Privileged group assessment checks.

This module implements checks relating to privileged Active Directory group 
membership.

Checks implemented within this module are intended to identify situations where 
a disproportionate number of enabled user accounts hold elevated administrative 
privileges.
"""

from ad_kit.core.privileged import (
    PRIVILEGED_GROUPS,
    get_privileged_group_members,
)
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding
from ad_kit.core.util import load_session, get_artefacts_dir


PRIVILEGED_GROUP_THRESHOLD = 10.0


def privileged_excessive_check(
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

    excessive_groups = []

    try:

        session_data = load_session()

    except RuntimeError:

        session_data = {}

    excluded_users = {
        user.lower()
        for user in session_data.get("excluded_users", [])
    }

    enabled_users = 0

    users_file = None

    try:

        users_file = (
            get_artefacts_dir()
            / "domain-users-filtered.txt"
        )

    except RuntimeError:

        pass

    if users_file is not None and users_file.exists():

        enabled_users = sum(
            1
            for line in users_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )

    elif session_data.get("domain_users_filtered_count"):

        enabled_users = session_data["domain_users_filtered_count"]

    else:

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

        parsing_users = False

        for line in users_output.splitlines():

            if "-Username-" in line:
                parsing_users = True
                continue

            if not parsing_users:
                continue

            if not line.strip():
                continue

            parts = line.split()

            if not parts:
                continue

            # NetExec user table parsing fallback
            account_name = parts[-4]

            if account_name.lower() in excluded_users:
                continue

            enabled_users += 1

    results["enabled_users"] = enabled_users

    # Privileged groups
    group_memberships = (
        get_privileged_group_members(
            dc_ip,
            username,
            password,
        )
    )

    for group in PRIVILEGED_GROUPS:

        members = group_memberships[group]
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
        if percentage >= PRIVILEGED_GROUP_THRESHOLD:

            excessive_groups.append((group, member_count, percentage))

    if excessive_groups:

        finding = load_finding("privileged_excessive", "PRIV-001")

        finding.evidence.append(
            f"The domain contained {enabled_users} enabled user accounts "
            "following exclusion of testing accounts used during the "
            "assessment."
        )

        for group, member_count, percentage in excessive_groups:

            finding.evidence.append(
                f"The '{group}' group contained {member_count} member(s)."
            )

            finding.evidence.append(
                f"'{group}' represented {percentage}% of the enabled user "
                "population."
            )

        finding.evidence.append(
            "The configured memberships exceeded the privileged group "
            f"assessment threshold of {PRIVILEGED_GROUP_THRESHOLD:.0f}%."
        )

        findings.append(finding)

    return results, findings