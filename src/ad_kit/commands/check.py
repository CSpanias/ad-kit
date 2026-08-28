"""
Assessment checks.
"""

from rich.table import Table

from ad_kit.core.checks import load_dc_ips
from ad_kit.checks.ldap import ldap_configuration_check
from ad_kit.core.console import console, print_section

#-------------------------------------------------------------------------------
# Main function
#-------------------------------------------------------------------------------
def run_checks() -> None:
    """
    Execute baseline assessment checks.
    """

    #---------------------------------------------------------------------------
    # LDAP Signing and Channel Binding
    #---------------------------------------------------------------------------
    print_section("LDAP Checks")

    results = []

    for dc_ip in load_dc_ips():
        results.append(ldap_configuration_check(dc_ip))

    table = Table()

    table.add_column("DC", style="cyan")
    table.add_column("LDAP Signing", style="green")
    table.add_column("Channel Binding", style="green")

    for result in results:
        table.add_row(
            result["dc_ip"],
            result["signing"],
            result["channel_binding"],
        )

    console.print(table)