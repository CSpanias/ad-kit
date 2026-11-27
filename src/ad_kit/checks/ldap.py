"""LDAP-related assessment checks."""

import re
from typing import TypedDict

from ad_kit.core.checks import (
    CheckEvidence,
    append_captured_evidence,
    capture_check_evidence,
    load_dc_hostnames,
    run_check,
)
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import format_counted_commentary, load_finding
from ad_kit.core.util import count_form, count_text, parallel_items, unique_hosts
from ad_kit.reporting.results import record_incomplete

_UNKNOWN = "[yellow]⚠ Unknown[/yellow]"


class LDAPResult(TypedDict):
    dc_hostname: str
    signing: str
    channel_binding: str
    anonymous_bind: str
    anonymous_users: int | None


def _anonymous_user_summary(results: list[LDAPResult]) -> str:
    confirmed = sum(
        1 for result in results
        if (users := result["anonymous_users"]) is not None and users > 0
    )
    empty = sum(result["anonymous_users"] == 0 for result in results)
    unknown = sum(result["anonymous_users"] is None for result in results)

    def controllers(count: int) -> str:
        return f"{count_text(count)} {count_form(count, 'domain controller', 'domain controllers')}"

    if confirmed and confirmed == len(results):
        scope = count_form(
            confirmed, "the affected domain controller", "all affected domain controllers"
        )
        return f"Anonymous user account enumeration was confirmed on {scope}."

    sentences = []
    if confirmed:
        sentences.append(
            f"Anonymous user account enumeration was confirmed on {controllers(confirmed)}."
        )
    if empty:
        sentences.append(f"No user accounts were returned on {controllers(empty)}.")
    if unknown:
        sentences.append(
            f"Anonymous user enumeration could not be confirmed on {controllers(unknown)}."
        )
    return " ".join(sentences)


def _check_controller(
    dc_hostname: str,
) -> tuple[LDAPResult, list[tuple[str, str]], list[CheckEvidence]]:
    result: LDAPResult = {
        "dc_hostname": dc_hostname,
        "signing": _UNKNOWN,
        "channel_binding": _UNKNOWN,
        "anonymous_bind": "[green]✓ Disabled[/green]",
        "anonymous_users": None,
    }
    incomplete: list[tuple[str, str]] = []
    anonymous_bind_confirmed = False

    with capture_check_evidence() as evidence:
        try:
            output = run_check(
                f"ldap-{dc_hostname}",
                ["nxc", "ldap", dc_hostname, "-u", "", "-p", ""],
                show_progress=False,
            )
        except CheckExecutionError as exc:
            incomplete.append(("LDAP", str(exc)))
            return result, incomplete, evidence

        for line in output.splitlines():
            lower = line.lower()
            if "signing:" in lower:
                start = lower.find("signing:")
                end = lower.find(")", start)
                if end != -1:
                    signing = lower[start + 8:end].strip()
                    result["signing"] = (
                        "[red]✗ Not Required[/red]" if signing == "none" else signing
                    )

            if "channel binding:" in lower:
                start = lower.find("channel binding:")
                end = lower.find(")", start)
                if end != -1:
                    binding = lower[start + 16:end].strip()
                    if binding == "no tls cert":
                        result["channel_binding"] = _UNKNOWN
                        incomplete.append((
                            "LDAP channel binding",
                            "TLS connection failed (NetExec reported No TLS cert); "
                            "channel binding could not be verified",
                        ))
                    else:
                        result["channel_binding"] = (
                            "[red]✗ Not Enforced[/red]" if binding == "never" else binding
                        )

            if "[+]" in line:
                success_message = line.split("[+]", 1)[1].strip()
                identity = success_message.split(":", 1)[0].strip()
                if identity.endswith(chr(92)):
                    anonymous_bind_confirmed = True

        if anonymous_bind_confirmed:
            evidence_name = f"ldap-anonymous-users-{dc_hostname}"
            try:
                users_output = run_check(
                    evidence_name,
                    ["nxc", "ldap", dc_hostname, "-u", "", "-p", "", "--users"],
                    show_progress=False,
                )
            except CheckExecutionError as exc:
                incomplete.append(("LDAP anonymous user enumeration", str(exc)))
            else:
                users_match = re.search(r"Enumerated\s+(\d+)\s+domain users:", users_output, re.I)
                if users_match:
                    result["anonymous_users"] = int(users_match.group(1))
                if result["anonymous_users"] is not None and result["anonymous_users"] > 0:
                    result["anonymous_bind"] = "[red]✗ Permitted[/red]"
                elif result["anonymous_users"] is not None:
                    result["anonymous_bind"] = "[green]✓ Disabled[/green]"
                else:
                    incomplete.append((
                        "LDAP anonymous user enumeration",
                        f"No confirmed user enumeration; see {evidence_name}.txt",
                    ))
        else:
            incomplete.append((
                "LDAP anonymous user enumeration",
                f"No confirmed anonymous bind; user enumeration not attempted; "
                f"see ldap-{dc_hostname}.txt",
            ))

    unknown = [
        label
        for key, label in (
            ("signing", "signing"),
            ("channel_binding", "channel binding"),
        )
        if result[key] == _UNKNOWN
    ]
    if unknown:
        incomplete.append(("LDAP", f"Unknown: {', '.join(unknown)}"))
    return result, incomplete, evidence


def ldap_check() -> tuple[list[dict], list[Finding]]:
    """Check each discovered Domain Controller and aggregate findings."""
    results = []
    for result, incomplete, evidence in parallel_items(
        unique_hosts(load_dc_hostnames()), "LDAP domain controllers", _check_controller
    ):
        append_captured_evidence(evidence)
        for check, reason in incomplete:
            record_incomplete(check, result["dc_hostname"], reason)
        results.append(result)

    findings: list[Finding] = []
    for key, status, finding_id in (
        ("signing", "[red]✗ Not Required[/red]", "LDAP-001"),
        ("channel_binding", "[red]✗ Not Enforced[/red]", "LDAP-002"),
        ("anonymous_bind", "[red]✗ Permitted[/red]", "LDAP-003"),
    ):
        affected = sorted({result["dc_hostname"] for result in results if result[key] == status})
        if affected:
            finding = load_finding("ldap", finding_id)
            format_counted_commentary(
                finding, len(affected), "Domain Controller (DC)", "Domain Controllers (DCs)"
            )
            if finding_id == "LDAP-003":
                affected_results = [
                    result for result in results
                    if result["anonymous_bind"] == "[red]✗ Permitted[/red]"
                ]
                finding.commentary = (
                    finding.commentary.rstrip() + " " + _anonymous_user_summary(affected_results)
                )
            finding.affected_assets.extend(affected)
            findings.append(finding)

    return sorted(results, key=lambda result: result["dc_hostname"]), findings
