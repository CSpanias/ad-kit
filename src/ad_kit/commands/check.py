from rich.table import Table

from ad_kit.core.checks import run_check
from ad_kit.core.util import load_session
from ad_kit.core.console import (
    console,
    print_section,
)


def ldap_signing_check(
    dc_ip: str,
) -> dict:
    """
    Check LDAP signing and channel binding.
    """

    output = run_check(
        "ldap-signing",
        ["nxc", "ldap", dc_ip],
    )

    signing = "Unknown"
    channel_binding = "Unknown"

    for line in output.splitlines():
        if "signing:" in line:
            if "signing:True" in line:
                signing = "Enabled"
            elif "signing:False" in line:
                signing = "Disabled"

        if "channel binding:" in line:
            if "channel binding:True" in line:
                channel_binding = "Enabled"
            elif "channel binding:False" in line:
                channel_binding = "Disabled"

    return {
        "signing": signing,
        "channel_binding": channel_binding,
    }

#-------------------------------------------------------------------------------
# Main function
#-------------------------------------------------------------------------------
def run_checks() -> None:
    """
    Execute baseline assessment checks.
    """

    session = load_session()

    dc_ip = session["dc_ip"]

    ldap_results = ldap_signing_check(
        dc_ip,
    )

    table = Table()

    table.add_column("Check", style="cyan")
    table.add_column("Result", style="green")

    table.add_row("LDAP Signing", ldap_results["signing"])
    table.add_row("Channel Binding", ldap_results["channel_binding"])

    console.print(table)