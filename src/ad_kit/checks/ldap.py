"""
LDAP-related assessment checks.
"""

from ad_kit.core.checks import run_check, load_dc_hostnames
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


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

    outputs = []
    for dc_hostname in dc_hostnames:
        dc_short_name = dc_hostname.split(".", 1)[0]
        outputs.append(
            run_check(
                f"ldap-{dc_short_name}",
                ["nxc", "ldap", dc_short_name, "-u", "", "-p", ""],
            )
        )

    hostname_map = {}

    for hostname in dc_hostnames:
        normalized_hostname = hostname.rstrip(".").casefold()
        hostname_map[normalized_hostname] = hostname
        hostname_map[normalized_hostname.split(".", 1)[0]] = hostname

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
    anonymous_bind_permitted: set[str] = set()
    anonymous_bind_rejected: set[str] = set()

    for line in "\n".join(outputs).splitlines():

        if not line.startswith("LDAP"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        dc_hostname = next(
            (
                hostname_map.get(part.strip("[](),:").rstrip(".").casefold())
                for part in parts
                if part.strip("[](),:").rstrip(".").casefold() in hostname_map
            ),
            None,
        )

        if dc_hostname is None:
            continue

        lower = line.lower()

        #-----------------------------------------------------------------------
        # LDAP SIGNING
        #-----------------------------------------------------------------------
        if "signing:" in lower:

            start = lower.find("signing:")
            end = lower.find(")", start)

            if start != -1 and end != -1:

                signing = lower[start + 8:end].strip()

                if signing == "none":

                    signing = "[red]✗ Not Required[/red]"
                    signing_not_enforced.append(dc_hostname)

                results[dc_hostname]["signing"] = signing

        #-----------------------------------------------------------------------
        # CHANNEL BINDING
        #-----------------------------------------------------------------------
        if "channel binding:" in lower:

            start = lower.find("channel binding:")
            end = lower.find(")", start)

            if start != -1 and end != -1:

                channel_binding = (lower[start + 16:end].strip())

                if channel_binding in {"never", "no tls cert"}:

                    channel_binding = ("[red]✗ Not Enforced[/red]")
                    channel_binding_not_enforced.append(dc_hostname)

                results[dc_hostname]["channel_binding"] = channel_binding

        #-----------------------------------------------------------------------
        # NULL BIND
        #-----------------------------------------------------------------------
        if "successful bind must be completed" in lower:
            anonymous_bind_rejected.add(dc_hostname)

        if "[+]" in line:
            success_message = line.split("[+]", 1)[1].strip()
            identity = success_message.split(":", 1)[0].strip()
            if identity.endswith("\\"):
                anonymous_bind_permitted.add(dc_hostname)

    for dc_hostname in anonymous_bind_rejected - anonymous_bind_permitted:
        results[dc_hostname]["anonymous_bind"] = "[green]✓ Disabled[/green]"

    for dc_hostname in anonymous_bind_permitted:
        results[dc_hostname]["anonymous_bind"] = "[red]✗ Permitted[/red]"

    #-----------------------------------------------------------------------
    # FINDINGS GENERATION
    #-----------------------------------------------------------------------
    
    # If any DC have LDAP signing not enforced, create finding
    if signing_not_enforced:

        finding = load_finding("ldap", "LDAP-001")
        finding.affected_assets.extend(sorted(set(signing_not_enforced)))
        findings.append(finding)

    # If any DC have LDAP channel binding not enforced, create finding
    if channel_binding_not_enforced:

        finding = load_finding("ldap", "LDAP-002")
        finding.affected_assets.extend(
            sorted(set(channel_binding_not_enforced))
        )
        findings.append(finding)

    # If any DC permits NULL binds, create finding
    if anonymous_bind_permitted:
        finding = load_finding("ldap", "LDAP-003")
        finding.affected_assets.extend(sorted(anonymous_bind_permitted))
        findings.append(finding)


    return (
        sorted(results.values(), key=lambda result: result["dc_hostname"]),
        findings,
    )