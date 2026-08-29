"""
Assessment checks.
"""

import typer

from rich.table import Table

from ad_kit.core.checks import (
    load_dc_ips, 
    load_domain_computers,
    load_dc_hostnames
)
from ad_kit.checks.ldap import ldap_configuration_check
from ad_kit.checks.passwords import password_policy_check
from ad_kit.checks.smb import smb_configuration_check
from ad_kit.core.console import console, print_section
from ad_kit.core.util import progress, load_session

#-------------------------------------------------------------------------------
# Main function
#-------------------------------------------------------------------------------
def run_checks() -> None:
    """
    Execute baseline assessment checks.
    """

    session_data = load_session()

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

    #---------------------------------------------------------------------------
    # SMB Signing and Version
    #---------------------------------------------------------------------------
    smb_results = []

    with progress("Checking SMB configuration..."):
        for host in load_domain_computers():
            smb_results.append(smb_configuration_check(host))

    dcs = {dc.lower() for dc in load_dc_hostnames()}

    dc_results = []
    host_results = []

    for result in smb_results:

        host = result["host"].lower()

        if host in dcs:
            dc_results.append(result)
        else:
            host_results.append(result)

    print_section("SMB Checks - Domain Controllers")

    dc_table = Table()

    dc_table.add_column("Host", style="cyan")
    dc_table.add_column("Signing", style="green")
    dc_table.add_column("SMBv1", style="green")

    for result in dc_results:
        dc_table.add_row(
            result["host"],
            result["signing"],
            result["smbv1"],
        )

    console.print(dc_table)

    print_section("SMB Checks - Hosts")

    host_table = Table()

    host_table.add_column("Host", style="cyan")
    host_table.add_column("Signing", style="green")
    host_table.add_column("SMBv1", style="green")

    for result in host_results:
        host_table.add_row(
            result["host"],
            result["signing"],
            result["smbv1"],
        )

    console.print(host_table)

    #---------------------------------------------------------------------------
    # Domain Password Policy
    #---------------------------------------------------------------------------
    print_section("Password Policy")

    std_pass = typer.prompt("Standard User Password", hide_input=True)

    with progress("Retrieving password policy..."):
        password_policy = password_policy_check(
            session_data["dc_ip"],
            session_data["standard_user"],
            std_pass,
        )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Minimum Length", password_policy["minimum_length"])
    table.add_row("Password History", password_policy["password_history"])
    table.add_row("Maximum Age", password_policy["maximum_age"])
    table.add_row("Minimum Age", password_policy["minimum_age"])
    table.add_row("Complexity", password_policy["complexity"])
    table.add_row("Observation Window", password_policy["observation_window"])
    table.add_row("Lockout Threshold", password_policy["lockout_threshold"])
    table.add_row("Lockout Duration", password_policy["lockout_duration"])

    console.print(table)