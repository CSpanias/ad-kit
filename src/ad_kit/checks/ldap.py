"""
LDAP-related assessment checks.
"""

from ad_kit.core.checks import run_check, load_dc_hostnames
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding
from ad_kit.core.util import get_artefacts_dir


def ldap_check() -> tuple[list[dict], list[Finding]]:
    """
    Execute LDAP configuration checks.

    Returns:
        A tuple containing:

        - Parsed LDAP configuration results for display.
        - Generated findings.
    """
    findings: list[Finding] = []

    dc_hostnames = load_dc_hostnames()

    dc_hostnames_file = (get_artefacts_dir() / "dc-hostnames.txt")

    output = run_check(
        "ldap",
        ["nxc", "ldap", str(dc_hostnames_file),
            "-u", "",
            "-p", "",
        ],
    )

    hostname_map = {}

    for hostname in dc_hostnames:
        hostname_map[hostname.split(".")[0].upper()] = hostname

    results = {}

    for dc_hostname in dc_hostnames:

        results[dc_hostname] = {
            "dc_hostname": dc_hostname,
            "signing": "[yellow]⚠ Unknown[/yellow]",
            "channel_binding": "[yellow]⚠ Unknown[/yellow]",
            "anonymous_bind": "[yellow]⚠ Unknown[/yellow]",
        }

    signing_not_enforced: list[str] = []
    channel_binding_not_enforced: list[str] = []

    for line in output.splitlines():

        if not line.startswith("LDAP"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        dc_name = parts[3]

        dc_hostname = hostname_map.get(dc_name)

        if dc_hostname is None:
            continue

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

                channel_binding = (lower[start + 16:end].strip())

                if channel_binding in {"never", "no tls cert"}:

                    channel_binding = ("[red]✗ Not Enforced[/red]")
                    channel_binding_not_enforced.append(dc_hostname)

                results[dc_hostname]["channel_binding"] = channel_binding

        # Anonymous Bind
        if ("successful bind must be completed" in lower):
            results[dc_hostname]["anonymous_bind"] = ("[green]✓ Disabled[/green]")


    if signing_not_enforced:

        finding = load_finding("ldap", "LDAP-001")
        finding.affected_assets.extend(sorted(set(signing_not_enforced)))
        findings.append(finding)

    if channel_binding_not_enforced:

        finding = load_finding("ldap", "LDAP-002")
        finding.affected_assets.extend(
            sorted(
                set(channel_binding_not_enforced)
            )
        )
        findings.append(finding)

    return (
        sorted(
            results.values(),
            key=lambda result: result["dc_hostname"],
        ),
        findings,
    )