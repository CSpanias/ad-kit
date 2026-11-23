"""LDAP-related assessment checks."""

import re

from ad_kit.core.checks import load_dc_hostnames, run_check
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding
from ad_kit.core.util import track_items
from ad_kit.reporting.results import record_incomplete


def ldap_check() -> tuple[list[dict], list[Finding]]:
    """
    Execute LDAP configuration checks.

    Each enumerated Domain Controller is targeted by its fully-qualified
    hostname (as recorded in ``dc-hostnames.txt`` during enumeration) so that
    NetExec can resolve the controller even when the assessment host has no
    domain search suffix configured.

    Returns:
        A tuple containing:

        - Parsed LDAP configuration results for display.
        - Generated findings.
    """
    findings: list[Finding] = []

    dc_hostnames = load_dc_hostnames()

    results: dict[str, dict] = {}

    signing_not_enforced: list[str] = []
    channel_binding_not_enforced: list[str] = []
    anonymous_bind_permitted: set[str] = set()
    failed_dcs: set[str] = set()

    for dc_hostname in track_items(dc_hostnames, "LDAP domain controllers"):

        results[dc_hostname] = {
            "dc_hostname": dc_hostname,
            "signing": "[yellow]⚠ Unknown[/yellow]",
            "channel_binding": "[yellow]⚠ Unknown[/yellow]",
            "anonymous_bind": "[yellow]⚠ Unknown[/yellow]",
        }

        # Target the fully-qualified hostname. NetExec performs the DNS
        # resolution itself, so a short name that may not resolve without a
        # domain search suffix is never relied upon.
        try:
            output = run_check(
                f"ldap-{dc_hostname}",
                ["nxc", "ldap", dc_hostname, "-u", "", "-p", ""],
            )
        except CheckExecutionError as exc:
            record_incomplete("LDAP", dc_hostname, str(exc))
            failed_dcs.add(dc_hostname)
            continue

        for line in output.splitlines():

            lower = line.lower()

            # LDAP Signing
            if "signing:" in lower:

                start = lower.find("signing:")
                end = lower.find(")", start)

                if start != -1 and end != -1:

                    signing = lower[start + 8:end].strip()

                    if signing == "none":

                        signing = "[red]✗ Not Required[/red]"
                        signing_not_enforced.append(dc_hostname)

                    results[dc_hostname]["signing"] = signing

            # Channel Binding
            if "channel binding:" in lower:

                start = lower.find("channel binding:")
                end = lower.find(")", start)

                if start != -1 and end != -1:

                    channel_binding = lower[start + 16:end].strip()

                    if channel_binding in {"never", "no tls cert"}:

                        channel_binding = "[red]✗ Not Enforced[/red]"
                        channel_binding_not_enforced.append(dc_hostname)

                    results[dc_hostname]["channel_binding"] = channel_binding

            # Anonymous (Null) Bind
            if "[+]" in line:
                success_message = line.split("[+]", 1)[1].strip()
                identity = success_message.split(":", 1)[0].strip()

                # A successful empty-username login ("DOMAIN\\" with no account
                # following the backslash) indicates anonymous bind is allowed.
                if identity.endswith(chr(92)):
                    anonymous_bind_permitted.add(dc_hostname)

        if dc_hostname in anonymous_bind_permitted:
            results[dc_hostname]["anonymous_bind"] = "[red]✗ Permitted[/red]"
            evidence_name = f"ldap-anonymous-users-{dc_hostname}"
            try:
                users_output = run_check(
                    evidence_name,
                    ["nxc", "ldap", dc_hostname, "-u", "", "-p", "", "--users"],
                )
            except CheckExecutionError as exc:
                record_incomplete("LDAP anonymous user enumeration", dc_hostname, str(exc))
            else:
                if not re.search(r"Enumerated\s+\d+\s+domain users:", users_output, re.I):
                    record_incomplete(
                        "LDAP anonymous user enumeration",
                        dc_hostname,
                        f"No confirmed user enumeration; see {evidence_name}.txt",
                    )

    for dc_hostname, result in results.items():
        if dc_hostname in failed_dcs:
            continue
        unknown = [
            label
            for key, label in (
                ("signing", "signing"),
                ("channel_binding", "channel binding"),
                ("anonymous_bind", "anonymous bind"),
            )
            if result[key] == "[yellow]⚠ Unknown[/yellow]"
        ]
        if unknown:
            record_incomplete("LDAP", dc_hostname, f"Unknown: {', '.join(unknown)}")

    if signing_not_enforced:

        finding = load_finding("ldap", "LDAP-001")
        finding.affected_assets.extend(sorted(set(signing_not_enforced)))
        findings.append(finding)

    if channel_binding_not_enforced:

        finding = load_finding("ldap", "LDAP-002")
        finding.affected_assets.extend(sorted(set(channel_binding_not_enforced)))
        findings.append(finding)

    if anonymous_bind_permitted:

        finding = load_finding("ldap", "LDAP-003")
        finding.affected_assets.extend(sorted(anonymous_bind_permitted))
        findings.append(finding)

    return (
        sorted(results.values(), key=lambda result: result["dc_hostname"]),
        findings,
    )