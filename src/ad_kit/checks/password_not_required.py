"""
Accounts configured without a required password assessment check.
"""

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


def password_not_required_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Identify enabled accounts with the PASSWD_NOTREQD flag set.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing the enabled account names and generated findings.
    """

    output = run_check(
        "password-not-required",
        [
            "nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
            "--password-not-required",
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
            if account:
                accounts.add(account)

    enabled_accounts = sorted(accounts)
    results = {
        "accounts": enabled_accounts,
        "account_count": len(enabled_accounts),
    }

    findings: list[Finding] = []
    if enabled_accounts:
        finding = load_finding("password_policy", "PASS-002")
        finding.evidence.append(
            f"A total of {len(enabled_accounts)} enabled account(s) have the "
            "PASSWD_NOTREQD flag set:"
        )
        finding.evidence.extend(
            f"`{account}`"
            for account in enabled_accounts
        )
        findings.append(finding)

    return results, findings
