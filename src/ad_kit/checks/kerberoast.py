"""
Kerberoasting assessment checks.

This module implements checks relating to Active Directory accounts associated 
with Service Principal Names (SPNs).

Checks implemented within this module are intended to identify accounts 
susceptible to Kerberoasting attacks.
"""

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding
from ad_kit.core.privileged import get_privileged_users
from ad_kit.core.util import get_artefacts_dir


def kerberoast_check(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Identify accounts susceptible to Kerberoasting attacks.

    Accounts associated with Service Principal Names (SPNs) permit retrieval 
    of Kerberos service tickets which may be subjected to offline password 
    cracking.

    Args:
        dc_ip:
            Domain Controller IP address.

        domain:
            Active Directory domain.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing:

        - Parsed Kerberoasting results.
        - Generated findings.
    """

    results = {
        "account_count": 0,
        "accounts": [],
    }

    findings: list[Finding] = []

    output_file = (
        get_artefacts_dir()
        / "kerberoastable-users.txt"
    )

    output = run_check(
        "kerberoast",
        [
            "GetUserSPNs.py",
            f"{domain}/{username}:{password}",
            "-dc-ip",
            dc_ip,
            "-request",
            "-outputfile",
            str(output_file),
        ],
    )

    if "No entries found!" in output:

        return results, findings

    accounts = []

    for line in output.splitlines():

        line = line.strip()

        if (
            not line
            or line.startswith("Impacket")
            or line.startswith("ServicePrincipalName")
            or line.startswith("---")
        ):
            continue

        # Typical output: # SQLSvc MSSQLSvc/sql01.domain.local:1433 ...
        parts = line.split()

        if not parts:
            continue

        account = parts[0]

        if account == "Name" or account.startswith("$krb5tgs$"):
            continue

        accounts.append(account)

    accounts = sorted(set(accounts))

    results["accounts"] = accounts
    results["account_count"] = len(accounts)

    if accounts:

        # KERB-001
        finding = load_finding("kerberoast", "KERB-001")

        for account in accounts:

            finding.evidence.append(
                f"Account '{account}' was associated with one or more Service "
                "Principal Names (SPNs)."
            )

            finding.evidence.append(
                "A Kerberos service ticket was successfully requested for "
                f"'{account}'."
            )

        finding.evidence.append(
            f"A total of {len(accounts)} Kerberoastable account(s) were "
            "identified."
        )

        findings.append(finding)

        # KERB-002
        privileged_users = get_privileged_users(
            dc_ip,
            username,
            password,
        )

        privileged_accounts = [
            account
            for account in accounts
            if account.lower() in privileged_users
        ]

        if privileged_accounts:

            finding = load_finding("kerberoast", "KERB-002")

            for account in sorted(privileged_accounts):

                finding.evidence.append(
                    f"Privileged account '{account}' was associated with one "
                    "or more Service Principal Names (SPNs)."
                )

                finding.evidence.append(
                    "A Kerberos service ticket was successfully requested for "
                    f"'{account}'."
                )

                finding.evidence.append(
                    "The account was identified as holding elevated privileges "
                    "within Active Directory."
                )

            finding.evidence.append(
                f"A total of {len(privileged_accounts)} privileged "
                "Kerberoastable account(s) were identified."
            )

            findings.append(finding)

    return results, findings