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
from ad_kit.core.util import parallel_items, unique_hosts
from ad_kit.reporting.results import record_incomplete

_UNKNOWN = "[yellow]⚠ Unknown[/yellow]"


class LDAPResult(TypedDict):
    dc_hostname: str
    signing: str
    channel_binding: str
    anonymous_bind: str


def _check_controller(
    dc_hostname: str,
) -> tuple[LDAPResult, list[tuple[str, str]], list[CheckEvidence]]:
    result: LDAPResult = {
        "dc_hostname": dc_hostname,
        "signing": _UNKNOWN,
        "channel_binding": _UNKNOWN,
        "anonymous_bind": _UNKNOWN,
    }
    incomplete: list[tuple[str, str]] = []

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
                    result["anonymous_bind"] = "[red]✗ Permitted[/red]"

        if result["anonymous_bind"] == "[red]✗ Permitted[/red]":
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
                if not re.search(r"Enumerated\s+\d+\s+domain users:", users_output, re.I):
                    incomplete.append((
                        "LDAP anonymous user enumeration",
                        f"No confirmed user enumeration; see {evidence_name}.txt",
                    ))

    unknown = [
        label
        for key, label in (
            ("signing", "signing"),
            ("channel_binding", "channel binding"),
            ("anonymous_bind", "anonymous bind"),
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
            finding.affected_assets.extend(affected)
            findings.append(finding)

    return sorted(results, key=lambda result: result["dc_hostname"]), findings
