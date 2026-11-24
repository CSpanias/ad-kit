"""
Privileged group assessment checks.

This module implements checks relating to privileged Active Directory group 
membership.

Checks implemented within this module are intended to identify situations where 
a disproportionate number of enabled user accounts hold elevated administrative 
privileges.
"""

import re

from ad_kit.core.checks import ANSI_ESCAPE_PATTERN, run_check
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding
from ad_kit.core.privileged import (
    PRIVILEGED_GROUPS,
    get_privileged_group_members,
)
from ad_kit.core.util import count_form, count_text, require_session

PRIVILEGED_GROUP_THRESHOLD = 10.0
ADMIN_COUNT_THRESHOLD = 25.0

ENABLED_USER_FILTER = (
    "(&(sAMAccountType=805306368)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)


def _enabled_user_accounts(output: str, excluded_users: set[str]) -> dict[str, bool]:
    accounts: dict[str, bool] = {}
    seen_names: set[str] = set()
    current: dict[str, str] | None = None

    def add_current() -> None:
        if current is None:
            return
        name = current.get("samaccountname", "").strip()
        admin_count = current.get("admincount", "0").strip()
        if not name or admin_count not in {"0", "1"} or name.casefold() in seen_names:
            raise CheckExecutionError(
                "privileged-enabled-users", [],
                stderr="Could not parse an enabled user entry; see privileged-enabled-users.txt.",
            )
        seen_names.add(name.casefold())
        if name.casefold() not in excluded_users:
            accounts[name] = admin_count == "1"

    for line in ANSI_ESCAPE_PATTERN.sub("", output).splitlines():
        match = re.match(r"^\s*LDAP\s+\S+\s+\d+\s+\S+\s+(.*)$", line)
        if not match:
            continue
        payload = match.group(1).strip()
        if payload.startswith(("[-]", "[!]")):
            raise CheckExecutionError(
                "privileged-enabled-users", [],
                stderr="NetExec reported an LDAP error; see privileged-enabled-users.txt.",
            )
        if re.match(r"^\[\+\]\s+Response for object:", payload, re.IGNORECASE):
            add_current()
            current = {}
            continue
        if current is None:
            continue
        attribute = re.match(r"^(sAMAccountName|adminCount)\s+(.+)$", payload, re.IGNORECASE)
        if attribute:
            key = attribute.group(1).casefold()
            if key in current:
                raise CheckExecutionError(
                    "privileged-enabled-users", [],
                    stderr="NetExec returned a duplicate user attribute.",
                )
            current[key] = attribute.group(2).strip()
        elif re.match(r"^(sAMAccountName|adminCount)\b", payload, re.IGNORECASE):
            raise CheckExecutionError(
                "privileged-enabled-users", [], stderr="NetExec returned an empty user attribute."
            )

    add_current()
    if not seen_names:
        raise CheckExecutionError(
            "privileged-enabled-users", [],
            stderr="NetExec returned no readable enabled users; see privileged-enabled-users.txt.",
        )
    if not accounts:
        raise CheckExecutionError(
            "privileged-enabled-users", [],
            stderr="No enabled users remain after applying account exclusions.",
        )
    return accounts


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
        "admin_count": {
            "member_count": 0,
            "percentage": 0.0,
            "members": [],
        },
    }

    findings: list[Finding] = []

    excessive_groups = []

    session_data = require_session()

    excluded_users = {
        user.casefold()
        for user in session_data.get("excluded_users", [])
    }

    users_output = run_check(
        "privileged-enabled-users",
        [
            "nxc", "ldap", dc_ip, "-u", username, "-p", password,
            "--query", ENABLED_USER_FILTER, "sAMAccountName adminCount",
        ],
        sensitive_values=[password],
    )
    users = _enabled_user_accounts(users_output, excluded_users)
    enabled_users = len(users)

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
            f"The domain contained {count_text(enabled_users)} enabled user "
            f"{count_form(enabled_users, 'account', 'accounts')} "
            "following exclusion of testing accounts used during the "
            "assessment."
        )

        for group, member_count, percentage in excessive_groups:

            finding.evidence.append(
                f"The {group} group contained {count_text(member_count)} "
                f"{count_form(member_count, 'member', 'members')} which "
                f"represented {percentage}% of the enabled user population."
            )

        findings.append(finding)

    admin_count_members = {
        name for name, protected in users.items() if protected
    }

    admin_count = len(admin_count_members)
    admin_count_percentage = (
        round((admin_count / enabled_users) * 100, 1)
        if enabled_users
        else 0
    )

    results["admin_count"] = {
        "member_count": admin_count,
        "percentage": admin_count_percentage,
        "members": sorted(admin_count_members),
    }

    if admin_count_percentage >= ADMIN_COUNT_THRESHOLD:

        finding = load_finding("privileged_excessive", "PRIV-002")
        finding.evidence.append(
            f"The domain contained {count_text(enabled_users)} enabled user "
            f"{count_form(enabled_users, 'account', 'accounts')} "
            "following exclusion of testing accounts used during the "
            "assessment."
        )
        finding.evidence.append(
            f"The `adminCount=1` attribute was set on {count_text(admin_count)} enabled user "
            f"{count_form(admin_count, 'account', 'accounts')}, representing "
            f"{admin_count_percentage}% of the enabled user "
            "population. This attribute can be stale and does not by itself "
            "confirm current privileged access."
        )
        findings.append(finding)

    return results, findings