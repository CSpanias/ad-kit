"""
Privileged account enumeration helpers.

This module provides shared functionality for retrieving membership of 
privileged Active Directory groups.

Functions implemented within this module are intended to support assessment 
checks requiring identification of privileged users and groups, including 
privilege assignment reviews, Kerberoasting analysis, delegation review, and
other privilege-related security assessments.
"""


import re

from ad_kit.core.checks import ANSI_ESCAPE_PATTERN, run_check
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.util import require_session, track_items

PRIVILEGED_GROUPS = (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "DNSAdmins",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Cert Publishers",
    "Exchange Windows Permissions",
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

    session_data = require_session()

    excluded_users = {
        user.casefold()
        for user in session_data.get("excluded_users", [])
    }

    groups = {}

    for group in track_items(PRIVILEGED_GROUPS, "Privileged groups"):

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
        authenticated = False
        empty_group = False
        member_rows = 0
        evidence_name = f"privileged-{group.lower().replace(' ', '-')}"
        for line in ANSI_ESCAPE_PATTERN.sub("", output).splitlines():
            match = re.match(r"^\s*LDAPS?\s+\S+\s+\d+\s+\S+\s+(.*)$", line, re.I)
            if not match:
                continue
            member = match.group(1).strip()
            if member.startswith("[+]"):
                authenticated = True
                continue
            if member.startswith("[-]"):
                if member.casefold() in {
                    f"[-] group '{group}' not found".casefold(),
                    f"[-] group '{group}' has no members".casefold(),
                }:
                    empty_group = True
                    continue
                raise CheckExecutionError(
                    evidence_name, [], stderr=f"NetExec reported an error; see {evidence_name}.txt."
                )
            if not member or member.startswith(("[*]", "[!]")):
                continue
            member_rows += 1
            if member.casefold() in excluded_users:
                continue
            members.append(member)

        if not authenticated or (not member_rows and not empty_group):
            raise CheckExecutionError(
                evidence_name, [],
                stderr=f"Could not determine group membership; see {evidence_name}.txt.",
            )
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

    users: set[str] = set()

    for members in groups.values():

        users.update(user.casefold() for user in members)

    return users


def get_account_privileged_groups(
    dc_ip: str, username: str, password: str, accounts: list[str]
) -> dict[str, list[str]]:
    """Return monitored direct memberships, keyed by case-folded account name."""
    wanted = {account.casefold() for account in accounts}
    memberships: dict[str, list[str]] = {}
    for group, members in get_privileged_group_members(dc_ip, username, password).items():
        for member in members:
            key = member.casefold()
            if key in wanted:
                memberships.setdefault(key, []).append(group)
    return memberships