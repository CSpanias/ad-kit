"""
Privileged account enumeration helpers.

This module provides shared functionality for retrieving membership of 
privileged Active Directory groups.

Functions implemented within this module are intended to support assessment 
checks requiring identification of privileged users and groups, including 
privilege assignment reviews, Kerberoasting analysis, delegation review, and
other privilege-related security assessments.
"""


from ad_kit.core.checks import run_check
from ad_kit.core.util import load_session


PRIVILEGED_GROUPS = (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "DNSAdmins",
)


def get_privileged_group_members(
    dc_ip: str,
    username: str,
    password: str,
) -> dict[str, list[str]]:
    """
    Retrieve members of privileged Active Directory groups.

    Returns:
        Dictionary containing privileged groups and their members.
    """

    try:

        session_data = load_session()

    except RuntimeError:

        session_data = {}

    excluded_users = {
        user.lower()
        for user in session_data.get("excluded_users", [])
    }

    groups = {}

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

            if not member:
                continue

            if member.lower() in excluded_users:
                continue

            members.append(member)

        groups[group] = sorted(set(members))

    return groups


def get_privileged_users(
    dc_ip: str,
    username: str,
    password: str,
) -> set[str]:
    """
    Retrieve all members of privileged Active Directory groups.
    """

    groups = get_privileged_group_members(
        dc_ip,
        username,
        password,
    )

    users = set()

    for members in groups.values():

        users.update(user.lower() for user in members)

    return users