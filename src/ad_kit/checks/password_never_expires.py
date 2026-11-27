"""
Accounts configured with non-expiring passwords assessment check.
"""

import re

from ad_kit.core.checks import ANSI_ESCAPE_PATTERN, NXC_LDAP_LINE, run_check
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import format_counted_commentary, load_finding
from ad_kit.core.util import count_form, count_text


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
    table_column: int | None = None
    table_rows = 0
    legacy_rows = 0
    no_entries = False
    search_started = False

    for line in ANSI_ESCAPE_PATTERN.sub("", output).splitlines():
        match = NXC_LDAP_LINE.match(line)
        if not match:
            continue
        payload = match.group(1)
        if payload.startswith("[+]"):
            search_started = True
            continue
        if payload.startswith("[-]"):
            if "no entries found!" in payload.lower():
                if search_started:
                    no_entries = True
            elif search_started:
                raise CheckExecutionError(
                    "password-never-expires", [],
                    stderr="NetExec reported an error; see password-never-expires.txt.",
                )
            continue
        if payload.startswith("[*]"):
            continue
        if "User:" in payload and "Status:" in payload:
            account, status = payload.split("User:", 1)[1].split("Status:", 1)
            account = account.strip()
            status = status.strip().casefold()
            if not account or status not in {"enabled", "disabled"}:
                raise CheckExecutionError(
                    "password-never-expires", [],
                    stderr="Could not parse a NetExec account status; see evidence.",
                )
            legacy_rows += 1
            if status == "enabled" and not account.endswith("$"):
                accounts.add(account)
            continue
        if re.match(r"^-Username-\s+-Last PW Set-", payload, re.IGNORECASE):
            table_column = payload.lower().index("-last pw set-")
            search_started = True
            continue
        if table_column is not None:
            account = payload[:table_column].strip()
            last_set = payload[table_column:].strip()
            if not account or (
                last_set and not re.fullmatch(
                    r"(?:<never>|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", last_set,
                    re.IGNORECASE,
                )
            ):
                raise CheckExecutionError(
                    "password-never-expires", [],
                    stderr="Could not parse a NetExec account row; see evidence.",
                )
            table_rows += 1
            if not account.endswith("$"):
                accounts.add(account)

    if (not table_rows and not legacy_rows and not no_entries) or (
        no_entries and (table_rows or legacy_rows)
    ):
        raise CheckExecutionError(
            "password-never-expires", [],
            stderr="Could not determine account results; see password-never-expires.txt.",
        )

    enabled_accounts = sorted(accounts)
    results = {
        "accounts": enabled_accounts,
        "account_count": len(enabled_accounts),
    }

    findings: list[Finding] = []
    if enabled_accounts:
        finding = load_finding("password_policy", "PASS-003")
        format_counted_commentary(finding, len(enabled_accounts), "account", "accounts")
        account_phrase = count_form(
            len(enabled_accounts), "account has a password", "accounts have passwords"
        )
        finding.evidence.append(
            f"A total of {count_text(len(enabled_accounts))} enabled user "
            f"{account_phrase} "
            "configured to never expire:"
        )
        finding.evidence.extend(
            f"`{account}`"
            for account in enabled_accounts
        )
        findings.append(finding)

    return results, findings
