"""
Assessment checks.
"""

from rich.table import Table

from ad_kit.checks.ldap import (
    ldap_configuration_check,
)

from ad_kit.core.console import (
    console,
    print_section,
)

from ad_kit.core.util import (
    load_session,
)

#-------------------------------------------------------------------------------
# Main function
#-------------------------------------------------------------------------------
def run_checks() -> None:
    """
    Execute baseline assessment checks.
    """

    session_data = load_session()

    dc_ip = session_data["dc_ip"]

    #---------------------------------------------------------------------------
    # LDAP Signing and Channel Binding
    #---------------------------------------------------------------------------
    print_section("LDAP Checks")

    ldap_results = ldap_configuration_check(dc_ip)

    table = Table()

    table.add_column("Check", style="cyan")
    table.add_column("Result", style="green")

    table.add_row("LDAP Signing", ldap_results["signing"])
    table.add_row("Channel Binding", ldap_results["channel_binding"])

    console.print(table)