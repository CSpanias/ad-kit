"""
LDAP-related assessment checks.
"""

from ad_kit.core.checks import load_dc_hostnames, run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


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
    anonymous_bind_rejected: set[str] = set()

    for dc_hostname in dc_hostnames:

        results[dc_hostname] = {
            "dc_hostname": dc_hostname,
            "signing": "[yellow]⚠ Unknown[/yellow]",
            "channel_binding": "[yellow]⚠ Unknown[/yellow]",
            "anonymous_bind": "[yellow]⚠ Unknown[/yellow]",
        }

        # Target the fully-qualified hostname. NetExec performs the DNS
        # resolution itself, so a short name that may not resolve without a
        # domain search suffix is never relied upon.
        output = run_check(
            f"ldap-{dc_hostname}",
            ["nxc", "ldap", dc_hostname, "-u", "", "-p", ""],
        )

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
            if "successful bind must be completed" in lower:
                anonymous_bind_rejected.add(dc_hostname)

            if "[+]" in line:
                success_message = line.split("[+]", 1)[1].strip()
                identity = success_message.split(":", 1)[0].strip()

                # A successful empty-username login ("DOMAIN\\" with no account
                # following the backslash) indicates anonymous bind is allowed.
                if identity.endswith(chr(92)):
                    anonymous_bind_permitted.add(dc_hostname)

    for dc_hostname in anonymous_bind_rejected:
        results[dc_hostname]["anonymous_bind"] = "[green]✓ Disabled[/green]"

    permitted_dc_hostnames = anonymous_bind_permitted - anonymous_bind_rejected

    for dc_hostname in permitted_dc_hostnames:
        results[dc_hostname]["anonymous_bind"] = "[red]✗ Permitted[/red]"

    if signing_not_enforced:

        finding = load_finding("ldap", "LDAP-001")
        finding.affected_assets.extend(sorted(set(signing_not_enforced)))
        findings.append(finding)

    if channel_binding_not_enforced:

        finding = load_finding("ldap", "LDAP-002")
        finding.affected_assets.extend(sorted(set(channel_binding_not_enforced)))
        findings.append(finding)

    if permitted_dc_hostnames:

        finding = load_finding("ldap", "LDAP-003")
        finding.affected_assets.extend(sorted(permitted_dc_hostnames))
        findings.append(finding)

    return (
        sorted(results.values(), key=lambda result: result["dc_hostname"]),
        findings,
    )