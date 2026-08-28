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
        Dictionary containing LDAP configuration results.
    """

    output = run_check(
        "ldap-configuration",
        ["nxc", "ldap", dc_ip],
    )

    signing = "Unknown"
    channel_binding = "Unknown"

    for line in output.splitlines():

        line = line.lower()

        if "signing:true" in line:
            signing = "Enabled"

        elif "signing:false" in line:
            signing = "Disabled"

        if "channel binding:true" in line:
            channel_binding = "Enabled"

        elif "channel binding:false" in line:
            channel_binding = "Disabled"

    return {
        "signing": signing,
        "channel_binding": channel_binding,
    }