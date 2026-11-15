"""
Checks for the status of built-in Active Directory accounts.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


DOMAIN_SID_PATTERN = re.compile(r"\b(S-1-5-21-(?:\d+-){2}\d+)\b", re.IGNORECASE)
ATTRIBUTE_PATTERN = re.compile(
    r"\b(sAMAccountName|userAccountControl)\s*[:=]\s*([^\s,]+)",
    re.IGNORECASE,
)


class BuiltinAccountResult(TypedDict):
    rid: int
    account_name: str
    enabled: bool


def _domain_sid(output: str) -> str:
    match = DOMAIN_SID_PATTERN.search(output)

    if match is None:
        raise RuntimeError("Could not determine the domain SID from NetExec output.")

    return match.group(1)


def _object_sid_filter(domain_sid: str, rid: int) -> str:
    sid_parts = domain_sid.split("-")

    if (
        len(sid_parts) != 7
        or sid_parts[:3] != ["S", "1", "5"]
        or sid_parts[3] != "21"
    ):
        raise ValueError(f"Invalid domain SID: {domain_sid}")

    subauthorities = [int(value) for value in sid_parts[3:]]
    subauthorities.append(rid)
    sid_bytes = (
        bytes((1, len(subauthorities)))
        + (5).to_bytes(6, "big")
        + b"".join(value.to_bytes(4, "little") for value in subauthorities)
    )
    escaped_sid = "".join(f"\\{value:02x}" for value in sid_bytes)

    return f"(objectSid={escaped_sid})"


def _account_attributes(output: str, rid: int) -> tuple[str, int]:
    attributes = {
        match.group(1).lower(): match.group(2).strip("()")
        for match in ATTRIBUTE_PATTERN.finditer(output)
    }

    account_name = attributes.get("samaccountname")
    user_account_control = attributes.get("useraccountcontrol")

    if account_name is None or user_account_control is None:
        raise RuntimeError(
            f"Could not determine the status of built-in account RID {rid}."
        )

    try:
        control_flags = int(user_account_control, 0)
    except ValueError as error:
        raise RuntimeError(
            f"Invalid userAccountControl value for built-in account RID {rid}."
        ) from error

    return account_name, control_flags


def builtin_accounts_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict[str, BuiltinAccountResult], list[Finding]]:
    """
    Check whether the built-in Administrator and Guest accounts are enabled.

    Accounts are identified by their well-known RIDs, so renamed accounts are
    still detected.
    """

    sid_output = run_check(
        "builtin-account-domain-sid",
        [
            "nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
            "--get-sid",
        ],
        sensitive_values=[password],
    )
    domain_sid = _domain_sid(sid_output)

    accounts: dict[str, BuiltinAccountResult] = {}

    for account_key, rid in (("administrator", 500), ("guest", 501)):
        query_output = run_check(
            f"builtin-account-rid-{rid}",
            [
                "nxc", "ldap", dc_ip,
                "-u", username,
                "-p", password,
                "--query", 
                _object_sid_filter(domain_sid, rid),
                "sAMAccountName userAccountControl",
            ],
            sensitive_values=[password],
        )
        account_name, control_flags = _account_attributes(query_output, rid)

        accounts[account_key] = {
            "rid": rid,
            "account_name": account_name,
            "enabled": not bool(control_flags & 0x2),
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
