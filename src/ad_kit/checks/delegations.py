"""
Delegation assessment checks.

This module implements checks relating to Active Directory Kerberos delegation.


Checks implemented within this module are intended to identify delegation 
configurations that may facilitate impersonation attacks, privilege escalation, 
or compromise of privileged accounts.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import ANSI_ESCAPE_PATTERN, NXC_LDAP_LINE, load_dc_hostnames, run_check
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding
from ad_kit.core.privileged import get_privileged_users
from ad_kit.core.util import count_form, count_text

IGNORED_DELEGATION_ACCOUNTS = {
        "azureadkerberos$",
    }

DELEGATION_ROW = re.compile(
    r"^(.*?)\s+(Unconstrained|Constrained w/ Protocol Transition|"
    r"Resource-Based Constrained|Constrained)\s+(.+)$"
)


class DelegationResult(TypedDict):
    unconstrained: list[str]
    protocol_transition: list[str]
    resource_based: list[tuple[str, str]]


def parse_delegation_output(
    output: str,
) -> tuple[set[str], set[str], set[tuple[str, str]]]:
    unconstrained: set[str] = set()
    protocol_transition: set[str] = set()
    resource_based: set[tuple[str, str]] = set()
    type_column = None
    row_count = 0
    no_entries = False

    for line in ANSI_ESCAPE_PATTERN.sub("", output).splitlines():
        if "Skipping item, cannot process due to error" in line:
            raise CheckExecutionError(
                "delegation-find", [], stderr="NetExec could not process a delegation entry."
            )
        if "[-]" in line:
            if "No entries found!" in line:
                no_entries = True
                continue
            raise CheckExecutionError(
                "delegation-find", [], stderr="NetExec reported an error; see delegation-find.txt."
            )

        match = NXC_LDAP_LINE.match(line)
        if not match:
            continue
        payload = match.group(1).rstrip()
        if "[+]" in payload or "[*]" in payload:
            continue
        if re.match(r"^AccountName\s+AccountType\s+DelegationType\s+DelegationRightsTo", payload):
            type_column = payload.index("AccountType")
            continue
        if type_column is None or re.fullmatch(r"[-\s]+", payload):
            continue

        row = DELEGATION_ROW.fullmatch(payload)
        if row is None:
            raise CheckExecutionError(
                "delegation-find", [], stderr="Could not parse a NetExec delegation table row."
            )
        identity = row.group(1)
        standard_type = re.fullmatch(r"(.+?)\s+(Person|Computer)", identity)
        if standard_type:
            account, account_type = standard_type.groups()
        elif len(identity) > type_column and identity[type_column - 1].isspace():
            account = identity[:type_column].strip()
            account_type = identity[type_column:].strip()
        else:
            parts = re.split(r"\s{2,}", identity, maxsplit=1)
            if len(parts) != 2:
                parts = identity.rsplit(None, 1)
            if len(parts) != 2:
                raise CheckExecutionError(
                    "delegation-find", [], stderr="Could not parse a NetExec delegation account."
                )
            account, account_type = parts
        if not account or not account_type:
            raise CheckExecutionError(
                "delegation-find", [], stderr="Could not parse a NetExec delegation account."
            )
        row_count += 1
        if row.group(2) == "Unconstrained":
            unconstrained.add(account)
        elif row.group(2) == "Constrained w/ Protocol Transition":
            protocol_transition.add(account)
        elif row.group(2) == "Resource-Based Constrained":
            resource_based.add((account, row.group(3).strip()))

    if (type_column is None or not row_count) and not no_entries:
        raise CheckExecutionError(
            "delegation-find", [], stderr="Could not parse the NetExec delegation table."
        )
    if no_entries and row_count:
        raise CheckExecutionError(
            "delegation-find", [], stderr="NetExec returned conflicting delegation results."
        )
    return unconstrained, protocol_transition, resource_based


def delegation_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[DelegationResult, list[Finding]]:
    """
    Assess Active Directory delegation configurations.

    This check identifies unconstrained delegation, constrained delegation with
    protocol transition, and resource-based constrained delegation.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing:

        - Parsed delegation results.
        - Generated findings.
    """

    results: DelegationResult = {
        "unconstrained": [],
        "protocol_transition": [],
        "resource_based": [],
    }

    findings: list[Finding] = []

    privileged_users = get_privileged_users(
        dc_ip,
        username,
        password,
    )

    privileged_unconstrained = []
    privileged_protocol_transition = []

    dc_hostnames = {
        dc.split(".")[0].lower()
        for dc in load_dc_hostnames()
    }

    output = run_check(
        "delegation-find",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "--find-delegation",
        ],
    )

    unconstrained_accounts, protocol_transition_accounts, resource_based = (
        parse_delegation_output(output)
    )
    unconstrained_accounts = {
        account for account in unconstrained_accounts
        if account.lower() not in IGNORED_DELEGATION_ACCOUNTS
        and not (account.endswith("$") and account.rstrip("$").lower() in dc_hostnames)
    }
    protocol_transition_accounts = {
        account for account in protocol_transition_accounts
        if account.lower() not in IGNORED_DELEGATION_ACCOUNTS
    }

    results["unconstrained"] = sorted(unconstrained_accounts)

    if unconstrained_accounts:

        finding = load_finding("delegations", "DELEG-001")

        for account in sorted(unconstrained_accounts):

            finding.evidence.append(
                f"Account '{account}' was configured with Unconstrained "
                "Delegation."
            )

        findings.append(finding)

        privileged_unconstrained = [
            account
            for account in unconstrained_accounts
            if account.lower() in privileged_users
        ]

    results["protocol_transition"] = sorted(protocol_transition_accounts)

    if protocol_transition_accounts:

        finding = load_finding("delegations", "DELEG-002")

        for account in sorted(protocol_transition_accounts):

            finding.evidence.append(
                f"Account '{account}' was configured with Kerberos Constrained "
                "Delegation and Protocol Transition."
            )

        findings.append(finding)

        privileged_protocol_transition = [
            account
            for account in protocol_transition_accounts
            if account.lower() in privileged_users
        ]

    results["resource_based"] = sorted(resource_based)
    if resource_based:
        finding = load_finding("delegations", "DELEG-004")
        finding.evidence_in_commentary = True
        for principal, resource in sorted(resource_based):
            finding.evidence.append(
                f"NetExec reported principal `{principal}` in the resource-based "
                f"delegation configuration for `{resource}`."
            )
        findings.append(finding)

    privileged_delegated_accounts = sorted(
        set(privileged_unconstrained + privileged_protocol_transition)
    )

    if privileged_delegated_accounts:

        finding = load_finding("delegations", "DELEG-003")

        for account in privileged_delegated_accounts:

            finding.evidence.append(
                f"Privileged account '{account}' was configured with a "
                "Kerberos delegation mechanism."
            )

        finding.evidence.append(
            f"A total of {count_text(len(privileged_delegated_accounts))} privileged "
            "delegated "
            f"{count_form(len(privileged_delegated_accounts), 'account was', 'accounts were')} "
            "identified."
        )

        findings.append(finding)

    return results, findings