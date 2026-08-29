"""
LDAP-related assessment checks.
"""

from ad_kit.core.checks import run_check


def ldap_configuration_check(
    dc_ip: str,
) -> dict:
    """
    Check LDAP signing and channel binding.

    Args:
        dc_ip: Domain Controller IP address.

    Returns:
        Dictionary containing LDAP configuration
        results.
    """

    output = run_check(
        f"ldap-{dc_ip}",
        ["nxc", "ldap", dc_ip],
    )

    signing = "Unknown"
    channel_binding = "Unknown"

    for line in output.splitlines():

        line = line.lower()

        if "signing:" in line:

            start = line.find("signing:")
            end = line.find(")", start)

            if start != -1 and end != -1:
                signing = line[start + 8:end].strip()

        if "channel binding:" in line:

            start = line.find("channel binding:")
            end = line.find(")", start)

            if start != -1 and end != -1:
                channel_binding = (
                    line[start + 16:end]
                    .strip()
                )

    if signing == "none":
        signing = "Not Required"
        
    if channel_binding == "no tls cert":
        channel_binding = "Not Configured"

    return {
        "dc_ip": dc_ip,
        "signing": signing,
        "channel_binding": channel_binding,
    }