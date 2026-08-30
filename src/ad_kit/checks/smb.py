"""
SMB-related assessment checks.
"""

from ad_kit.core.checks import run_check


def smb_configuration_check(
    host: str,
) -> dict:
    """
    Check SMB signing and SMBv1 support.

    Args:
        host: Hostname or FQDN.

    Returns:
        Dictionary containing SMB configuration
        results.
    """

    output = run_check(
        f"smb-{host}",
        ["nxc", "smb", host],
    )

    signing = "Unknown"
    smbv1 = "Unknown"

    for line in output.splitlines():

        line = line.lower()

        if "signing:" in line:

            start = line.find("signing:")
            end = line.find(")", start)

            if start != -1 and end != -1:
                signing = line[start + 8:end].strip()

        if "smbv1:" in line:

            start = line.find("smbv1:")
            end = line.find(")", start)

            if start != -1 and end != -1:
                smbv1 = line[start + 6:end].strip()

    if signing.lower() == "true":
        signing = "[green]Enabled[/green]"

    elif signing.lower() == "false":
        signing = "[yellow]⚠ Disabled[/yellow]"

    if smbv1.lower() == "none":
        smbv1 = "[green]Disabled[/green]"

    elif smbv1.lower() == "true":
        smbv1 = "[yellow]⚠ Enabled[/yellow]"


    return {
        "host": host,
        "signing": signing,
        "smbv1": smbv1,
    }