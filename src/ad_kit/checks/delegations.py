"""
Delegation assessment checks.

This module implements checks relating to Active Directory Kerberos delegation.


Checks implemented within this module are intended to identify delegation 
configurations that may facilitate impersonation attacks, privilege escalation, 
or compromise of privileged accounts.
"""

from ad_kit.core.checks import (
    load_dc_hostnames,
    run_check,
)
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


def delegation_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Assess Active Directory delegation configurations.

    This check identifies accounts configured for unconstrained delegation and 
    Kerberos constrained delegation with protocol transition.

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

    results = {
        "unconstrained": [],
        "protocol_transition": [],
    }

    findings: list[Finding] = []

    dc_hostnames = {
        dc.split(".")[0].lower()
        for dc in load_dc_hostnames()
    }

    # Unconstrained Delegation
    output = run_check(
        "delegation-unconstrained",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "--trusted-for-delegation",
        ],
    )

    unconstrained_accounts = []

    for line in output.splitlines():

        if (
            "[+]" in line
            or "[*]" in line
            or not line.strip()
        ):
            continue

        account = line.split()[-1].strip()

        if not account:
            continue

        # Ignore Domain Controllers.
        if account.endswith("$"):

            hostname = account.rstrip("$").lower()

            if hostname in dc_hostnames:
                continue

        unconstrained_accounts.append(account)

    results["unconstrained"] = sorted(unconstrained_accounts)

    if unconstrained_accounts:

        finding = load_finding("delegations", "DELEG-001")

        for account in sorted(unconstrained_accounts):

            finding.evidence.append(
                f"Account '{account}' was configured with Unconstrained "
                "Delegation."
            )

        findings.append(finding)

    # Constrained Delegation with Protocol Transition
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

    protocol_transition_accounts = []

    for line in output.splitlines():

        if (
            "[+]" in line
            or "[*]" in line
            or not line.strip()
            or "AccountName" in line
            or "--------" in line
        ):
            continue

        if "Constrained w/ Protocol Transition" not in line:
            continue

        parts = line.split()

        if not parts:
            continue

        account = parts[-4]

        protocol_transition_accounts.append(account)

    results["protocol_transition"] = sorted(protocol_transition_accounts)

    if protocol_transition_accounts:

        finding = load_finding("delegations", "DELEG-002")

        for account in sorted(protocol_transition_accounts):

            finding.evidence.append(
                f"Account '{account}' was configured with Kerberos Constrained "
                "Delegation and Protocol Transition."
            )

        findings.append(finding)

    return results, findings