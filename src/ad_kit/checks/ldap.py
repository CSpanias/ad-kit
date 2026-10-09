"""
LDAP-related assessment checks.
"""

from ad_kit.core.checks import run_check, load_dc_hostnames
from ad_kit.core.util import get_artefacts_dir
from ad_kit.core.finding import Finding
from ad_kit.findings.ldap_config import (
    LDAP_SIGNING_NOT_ENFORCED,
    LDAP_CHANNEL_BINDING_NOT_ENFORCED,
)


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
                    finding = LDAP_SIGNING_NOT_ENFORCED.copy()
                    finding.affected_assets.append(dc_hostname)
                    findings.append(finding)

                results[dc_hostname]["signing"] = signing

        # Channel Binding
        if "channel binding:" in lower:

            start = lower.find("channel binding:")
            end = lower.find(")", start)

            if start != -1 and end != -1:

                channel_binding = (lower[start + 16:end].strip())

                if channel_binding == "no tls cert":

                    channel_binding = "[red]✗ Not Configured[/red]"

                    finding = LDAP_CHANNEL_BINDING_NOT_ENFORCED.copy()
                    finding.affected_assets.append(dc_hostname)
                    findings.append(finding)

                results[dc_hostname]["channel_binding"] = channel_binding

        # Anonymous Bind
        if ("successful bind must be completed" in lower):
            results[dc_hostname]["anonymous_bind"] = ("[green]✓ Disabled[/green]")

    return (
        sorted(
            results.values(),
            key=lambda result: result["dc_hostname"],
        ),
        findings,
    )