"""
Checks for the status of built-in Active Directory accounts.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import parse_domain_sid, run_check
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding, load_finding_definition
from ad_kit.core.util import track_items
from ad_kit.reporting.results import record_incomplete

ACCOUNT_NAME_PATTERN = re.compile(r"\bsAMAccountName:[ \t]*([^\r\n]+)", re.IGNORECASE)
ENABLED_PATTERN = re.compile(r"\bEnabled:\s*(Yes|No)\b", re.IGNORECASE)
USER_SID_PATTERN = re.compile(
    r"\bUser SID:\s*(S-1-5-21-(?:\d+-){3}\d+)\b",
    re.IGNORECASE,
)


class BuiltinAccountResult(TypedDict):
    rid: int
    account_name: str
    enabled: bool | None


def _account_status(
    output: str,
    expected_sid: str,
) -> tuple[str, bool]:
    account_name_match = ACCOUNT_NAME_PATTERN.search(output)
    enabled_match = ENABLED_PATTERN.search(output)
    sid_match = USER_SID_PATTERN.search(output)

    if (
        account_name_match is None
        or not account_name_match.group(1).strip()
        or enabled_match is None
        or sid_match is None
    ):
        raise RuntimeError(
            f"Could not determine the status of built-in account RID "
            f"{expected_sid.rsplit('-', 1)[-1]} from NetExec output."
        )

    if sid_match.group(1).casefold() != expected_sid.casefold():
        raise RuntimeError(
            f"NetExec returned SID {sid_match.group(1)}; expected {expected_sid}."
        )

    return account_name_match.group(1).strip(), enabled_match.group(1).lower() == "yes"


def builtin_accounts_check(
    dc_ip: str,
    domain: str,
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
    try:
        sid_output = run_check(
            "builtin-account-domain-sid",
            ["nxc", "ldap", dc_ip, "-u", username, "-p", password, "--get-sid"],
            sensitive_values=[password],
        )
        domain_sid = parse_domain_sid(sid_output)
    except (CheckExecutionError, RuntimeError) as exc:
        record_incomplete("Built-in accounts", dc_ip, str(exc))
        return {
            "administrator": {"rid": 500, "account_name": "Unknown", "enabled": None},
            "guest": {"rid": 501, "account_name": "Unknown", "enabled": None},
        }, []

    for account_key, rid in track_items((
        ("administrator", 500),
        ("guest", 501),
    ), "Built-in accounts"):
        sid = f"{domain_sid}-{rid}"
        try:
            lookup = run_check(
                f"builtin-account-lookup-{rid}",
                [
                    "bloodyAD", "-u", username, "-p", password, "-d", domain,
                    "--dc-ip", dc_ip, "get", "object", sid, "--attr", "sAMAccountName",
                ],
                sensitive_values=[password],
            )
            match = ACCOUNT_NAME_PATTERN.search(lookup)
            if match is None or not match.group(1).strip():
                raise RuntimeError(f"Could not resolve built-in account SID {sid}.")
            output = run_check(
                f"builtin-account-rid-{rid}",
                [
                    "nxc", "ldap", dc_ip, "-u", username, "-p", password,
                    "-M", "whoami", "-o", f"USER={match.group(1).strip()}",
                ],
                sensitive_values=[password],
            )
            returned_name, enabled = _account_status(output, sid)
        except (CheckExecutionError, RuntimeError) as exc:
            record_incomplete("Built-in account", sid, str(exc))
            accounts[account_key] = {"rid": rid, "account_name": "Unknown", "enabled": None}
            continue

        accounts[account_key] = {
            "rid": rid,
            "account_name": returned_name,
            "enabled": enabled,
        }

    findings: list[Finding] = []
    administrator = accounts["administrator"]
    guest = accounts["guest"]

    if administrator["enabled"] is True:
        finding = load_finding("privileged_excessive", "PRIV-004")
        name_is_administrator = administrator["account_name"].casefold() == "administrator"
        guidance = load_finding_definition("privileged_excessive", "PRIV-004")[
            "name_guidance"
        ]["administrator" if name_is_administrator else "other"]
        if not name_is_administrator:
            finding.commentary = finding.commentary.strip() + "\n\n" + guidance["commentary"]
        finding.remediation = finding.remediation.strip() + "\n\n" + guidance["remediation"]
        finding.evidence.append(
            f"The built-in Administrator account (RID 500), named "
            f"`{administrator['account_name']}`, was enabled."
        )
        findings.append(finding)

    if guest["enabled"] is True:
        finding = load_finding("privileged_excessive", "PRIV-003")
        finding.evidence.append(
            f"The built-in Guest account (RID 501), named "
            f"`{guest['account_name']}`, was enabled."
        )
        findings.append(finding)

    return accounts, findings
