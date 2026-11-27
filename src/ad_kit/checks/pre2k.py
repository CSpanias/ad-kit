"""
Pre-Windows 2000 computer account assessment checks.

This module implements checks relating to pre-created Active Directory computer 
accounts susceptible to the legacy pre-Windows 2000 machine account password
convention.

Checks implemented within this module are intended to identify situations where 
Kerberos authentication can be achieved using predictable default machine 
account credentials.
"""

import re

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import format_counted_commentary, load_finding


def pre2k_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Identify pre-created computer accounts that permit authentication using the 
    legacy pre-Windows 2000 machine account password convention.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing:

        - Parsed pre-created computer account results.
        - Generated findings.
    """

    output = run_check(
        "pre2k",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "-M",
            "pre2k",
        ],
        kerberos_dc=dc_ip,
    )

    results = {
        "accounts_found": 0,
        "accounts": [],
        "tgt_obtained": False,
        "account_tgts": {},
    }

    findings: list[Finding] = []

    for line in output.splitlines():

        lower_line = line.lower()

        if "pre-created computer account:" in lower_line:

            account = (line.split(":")[-1].strip())
            results["accounts"].append(account)

        elif match := re.search(r"\bfound\s+(\d+)\s+pre-created computer accounts?\b", lower_line):

            results["accounts_found"] = int(match.group(1))

        elif "successfully obtained tgt" in lower_line:

            results["tgt_obtained"] = True

        match = re.search(
            r"\b(successfully obtained tgt|failed to get tgt|error obtaining tgt)"
            r"\s+for\s+([^\s@:]+)@",
            lower_line,
        )
        if match:
            account = match.group(2).removesuffix("$")
            results["account_tgts"][account] = {
                "successfully obtained tgt": "Successful",
                "failed to get tgt": "Failed",
                "error obtaining tgt": "Error",
            }[match.group(1)]

    if (
        results["accounts_found"] > 0
        and results["tgt_obtained"]
    ):

        finding = load_finding("pre2k", "PRE2K-001")
        format_counted_commentary(finding, results["accounts_found"], "account", "accounts")

        if len(results["accounts"]) == 1:

            finding.evidence.append(
                f"Pre-created computer account '{results['accounts'][0]}' was "
                "identified."
            )

        elif len(results["accounts"]) > 1:

            finding.evidence.append(
                "Multiple pre-created computer accounts were identified."
            )

        finding.evidence.append(
            "A Kerberos TGT was successfully "
            "obtained using the default machine account password convention."
        )

        findings.append(finding)

    return results, findings