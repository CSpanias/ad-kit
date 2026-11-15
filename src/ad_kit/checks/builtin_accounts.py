"""
Checks for the status of built-in Active Directory accounts.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding

ACCOUNT_NAME_PATTERN = re.compile(r"\bsAMAccountName:\s*(\S+)", re.IGNORECASE)
ENABLED_PATTERN = re.compile(r"\bEnabled:\s*(Yes|No)\b", re.IGNORECASE)
USER_SID_PATTERN = re.compile(
    r"\bUser SID:\s*(S-1-5-21-(?:\d+-){3}\d+)\b",
    re.IGNORECASE,
)


class BuiltinAccountResult(TypedDict):
    rid: int
    account_name: str
    enabled: bool


def _account_status(
    output: str,
    expected_rid: int,
) -> tuple[str, bool]:
    account_name_match = ACCOUNT_NAME_PATTERN.search(output)
    enabled_match = ENABLED_PATTERN.search(output)
    sid_match = USER_SID_PATTERN.search(output)

    if account_name_match is None or enabled_match is None or sid_match is None:
        raise RuntimeError(
            f"Could not determine the status of built-in account RID "
            f"{expected_rid} from NetExec output."
        )

    actual_rid = int(sid_match.group(1).rsplit("-", 1)[1])

    if actual_rid != expected_rid:
        raise RuntimeError(
            f"NetExec returned SID RID {actual_rid}; expected "
            f"built-in account RID {expected_rid}."
        )

    return account_name_match.group(1), enabled_match.group(1).lower() == "yes"


def builtin_accounts_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict[str, BuiltinAccountResult], list[Finding]]:
    """
    Check whether the built-in Administrator and Guest accounts are enabled.

    The returned account SID is validated against the well-known RID, so the
    check does not mistake an unrelated account with the same name for a
    built-in account.
    """

    accounts: dict[str, BuiltinAccountResult] = {}

    for account_key, account_name, rid in (
        ("administrator", "Administrator", 500),
        ("guest", "Guest", 501),
    ):
        output = run_check(
            f"builtin-account-rid-{rid}",
            [
                "nxc", "ldap", dc_ip,
                "-u", username,
                "-p", password,
                "-M", "whoami",
                "-o", f"USER={account_name}",
            ],
            sensitive_values=[password],
        )
        returned_name, enabled = _account_status(output, rid)

        accounts[account_key] = {
            "rid": rid,
            "account_name": returned_name,
            "enabled": enabled,
        }

    findings: list[Finding] = []
    guest = accounts["guest"]

    if guest["enabled"]:
        finding = load_finding("privileged_excessive", "PRIV-003")
        finding.evidence.append(
            f"The built-in Guest account (RID 501), named "
            f"`{guest['account_name']}`, is enabled."
        )
        findings.append(finding)

    return accounts, findings
