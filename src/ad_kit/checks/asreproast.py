"""
AS-REP roasting assessment checks.

This module implements checks relating to Active Directory accounts configured 
without Kerberos pre-authentication.

Checks implemented within this module are intended to identify accounts 
susceptible to AS-REP roasting attacks.
"""

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import format_counted_commentary, load_finding
from ad_kit.core.privileged import get_privileged_users
from ad_kit.core.util import count_form, count_text, get_artefacts_dir


def _parse_asrep_account(
    hash_line: str,
) -> str | None:
    """
    Extract the account name from a Hashcat-formatted AS-REP hash.
    """

    fields = hash_line.split("$", 3)
    if len(fields) != 4 or fields[1] != "krb5asrep":
        return None

    principal = fields[3].split(":", 1)[0]
    account, separator, _domain = principal.partition("@")
    if not separator or not account:
        return None

    return account


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
            "-dc-ip", dc_ip,
            "-format", "hashcat",
            "-outputfile", str(output_file),
            "-usersfile", str(users_file),
            "-no-pass",
        ],
        kerberos_dc=dc_ip,
    )

    if not output_file.exists():

        return results, findings

    accounts = []

    for line in output_file.read_text(encoding="utf-8").splitlines():

        line = line.strip()

        if not line:
            continue

        account = _parse_asrep_account(line)
        if account is None:
            continue

        accounts.append(account)

    results["accounts"] = sorted(set(accounts))
    results["account_count"] = len(results["accounts"])

    if results["accounts"]:

        finding = load_finding("asreproast", "ASREP-001")
        format_counted_commentary(finding, results["account_count"], "account", "accounts")

        for account in results["accounts"]:

            finding.evidence.append(
                f"Account '{account}' was configured without Kerberos "
                "pre-authentication."
            )

        finding.evidence.append(
            f"A total of {count_text(results['account_count'])} AS-REP roastable "
            f"{count_form(results['account_count'], 'account was', 'accounts were')} identified."
        )

        findings.append(finding)

    return results, findings


def asreproast_privileged_check(
    dc_ip: str,
    accounts: list[str],
    username: str,
    password: str,
) -> tuple[list[str], list[Finding]]:
    """
    Identify AS-REP roastable accounts that belong to monitored privileged
    groups.
    """

    privileged_users = get_privileged_users(
        dc_ip,
        username,
        password,
    )

    privileged_accounts_by_name = {
        account.lower(): account
        for account in accounts
        if account.lower() in privileged_users
    }
    privileged_accounts = sorted(
        privileged_accounts_by_name.values(),
        key=str.lower,
    )

    findings: list[Finding] = []
    if privileged_accounts:
        finding = load_finding("asreproast", "ASREP-002")
        format_counted_commentary(finding, len(privileged_accounts), "account", "accounts")

        for account in privileged_accounts:
            finding.evidence.append(
                f"Account '{account}' was configured without Kerberos "
                "pre-authentication and is a member of a monitored privileged "
                "group."
            )

        finding.evidence.append(
            f"A total of {count_text(len(privileged_accounts))} privileged AS-REP "
            f"roastable {count_form(len(privileged_accounts), 'account was', 'accounts were')} "
            "identified."
        )
        findings.append(finding)

    return privileged_accounts, findings