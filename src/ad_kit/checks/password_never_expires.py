"""
Accounts configured with non-expiring passwords assessment check.
"""

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


def password_never_expires_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Identify enabled user accounts configured with non-expiring passwords.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing the enabled user account names and generated findings.
    """

    output = run_check(
        "password-never-expires",
        [
            "nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
            "--password-never-expires",
        ],
    )

    accounts: set[str] = set()

    for line in output.splitlines():
        if "User:" not in line or "Status:" not in line:
            continue

        account_status = line.split("User:", 1)[1]
        account, status = account_status.split("Status:", 1)

        if status.strip().casefold() == "enabled":
            account = account.strip()
            # Machine accounts (sAMAccountName ends with '$') are excluded:
            # DONT_EXPIRE_PASSWD is expected on them and their secret rotates
            # independently of this flag.
            if account and not account.endswith("$"):
                accounts.add(account)

    enabled_accounts = sorted(accounts)
    results = {
        "accounts": enabled_accounts,
        "account_count": len(enabled_accounts),
    }

    findings: list[Finding] = []
    if enabled_accounts:
        finding = load_finding("password_policy", "PASS-003")
        finding.evidence.append(
            f"A total of {len(enabled_accounts)} enabled user account(s) have "
            "passwords configured to never expire:"
        )
        finding.evidence.extend(
            f"`{account}`"
            for account in enabled_accounts
        )
        findings.append(finding)

    return results, findings
