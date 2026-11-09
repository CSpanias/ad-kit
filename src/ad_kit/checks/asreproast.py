"""
AS-REP roasting assessment checks.

This module implements checks relating to Active Directory accounts configured 
without Kerberos pre-authentication.

Checks implemented within this module are intended to identify accounts 
susceptible to AS-REP roasting attacks.
"""

from pathlib import Path

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding
from ad_kit.core.util import (
    get_artefacts_dir,
    load_session,
)


def asreproast_check(
    dc_ip: str,
    domain: str,
) -> tuple[dict, list[Finding]]:
    """
    Identify accounts susceptible to AS-REP roasting attacks.

    Accounts configured without Kerberos pre-authentication permit retrieval of
    AS-REP responses without prior authentication and may therefore be 
    susceptible to offline password cracking.

    Args:
        dc_ip:
            Domain Controller IP address.

        domain:
            Active Directory domain name.

    Returns:
        A tuple containing:

        - Parsed AS-REP roasting results.
        - Generated findings.
    """

    results = {
        "account_count": 0,
        "accounts": [],
    }

    findings: list[Finding] = []

    session_data = load_session()

    users_file = (
        get_artefacts_dir()
        / "domain-users-filtered.txt"
    )

    if not users_file.exists():

        raise RuntimeError(
            "Filtered domain user list not found. Run 'ad-kit enum' before "
            "executing AS-REP roasting checks."
        )

    output_file = (
        get_artefacts_dir()
        / "asreproastable-users.txt"
    )

    run_check(
        "asreproast",
        [
            "GetNPUsers.py",
            f"{domain}/",
            "-dc-ip",
            dc_ip,
            "-format",
            "hashcat",
            "-outputfile",
            str(output_file),
            "-usersfile",
            str(users_file),
            "-no-pass",
        ],
    )

    if not output_file.exists():

        return results, findings

    accounts = []

    for line in output_file.read_text(encoding="utf-8").splitlines():

        line = line.strip()

        if not line:
            continue

        # Example: $krb5asrep$23$user@DOMAIN:...
        try:

            account = line.split("$")[-1].split("@")[0]

        except (IndexError, ValueError):

            continue

        accounts.append(account)

    results["accounts"] = sorted(set(accounts))
    results["account_count"] = len(results["accounts"])

    if results["accounts"]:

        finding = load_finding("asreproast", "ASREP-001")

        for account in results["accounts"]:

            finding.evidence.append(
                f"Account '{account}' was configured without Kerberos "
                "pre-authentication."
            )

        finding.evidence.append(
            f"{results['account_count']} AS-REP roastable account(s) were "
            "identified."
        )

        findings.append(finding)

    return results, findings