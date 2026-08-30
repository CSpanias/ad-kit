"""
Assessment checks.
"""

import typer

from rich.table import Table

from ad_kit.core.checks import (
    load_domain_computers,
    load_dc_hostnames,
    validate_credentials
)
from ad_kit.checks.ldap import ldap_check
from ad_kit.checks.passwords import (
    password_policy_check, 
    password_policy_assessment
)
from ad_kit.checks.smb import smb_configuration_check
from ad_kit.core.console import console, print_section, print_error, print_success
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
    # Unauthenticated Checks
    #---------------------------------------------------------------------------

    #---------------------------------------------------------------------------
    # LDAP Checks
    #---------------------------------------------------------------------------
    print_section("LDAP Checks")

    ldap_results = []

    with progress("Checking LDAP configuration..."):
            ldap_results = ldap_check()

    # LDAP Results Table
    table = Table()

    table.add_column("DC", style="cyan")
    table.add_column("LDAP Signing", style="green")
    table.add_column("Channel Binding", style="green")
    table.add_column("Anonymous Bind", style="green")

    for result in ldap_results:
        table.add_row(
            result["dc_hostname"],
            result["signing"],
            result["channel_binding"],
            result["anonymous_bind"],
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
    # Authenticated Checks
    #---------------------------------------------------------------------------
    print_section("Authenticated Checks")

    while True:

        std_pass = typer.prompt("Standard User Password", hide_input=True)

        with progress("Validating credentials..."):

            status = validate_credentials(
                session_data["dc_ip"],
                session_data["standard_user"],
                std_pass,
            )

        if status == "valid":
            print_success("Authentication succeeded.")
            break

        if status == "locked":
            print_error("Account is locked out.")

        elif status == "invalid":
            print_error("Invalid credentials.")

        else:
            print_error("Unable to validate credentials.")

        if not typer.confirm("Try again?", default=True):
            return

    #---------------------------------------------------------------------------
    # Domain Password Policy
    #---------------------------------------------------------------------------
    print_section("Password Policy")

    with progress("Retrieving password policy..."):
        password_policy = password_policy_check(
            session_data["dc_ip"],
            session_data["standard_user"],
            std_pass,
        )

    assessment = password_policy_assessment(password_policy)

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Assessment", style="yellow")

    table.add_row(
        "Minimum Length", 
        password_policy["minimum_length"],
        assessment["minimum_length"]
    )
    
    table.add_row(
        "Password History", 
        password_policy["password_history"],
        assessment["password_history"]
    )

    table.add_row(
        "Maximum Age", 
        password_policy["maximum_age"],
        assessment["maximum_age"]
    )

    table.add_row(
        "Minimum Age", 
        password_policy["minimum_age"],
        assessment["minimum_age"]
    )

    table.add_row(
        "Complexity", 
        password_policy["complexity"],
        assessment["complexity"]
    )

    table.add_row(
        "Observation Window", 
        password_policy["observation_window"],
        assessment["observation_window"]
    )

    table.add_row(
        "Lockout Threshold", 
        password_policy["lockout_threshold"],
        assessment["lockout_threshold"]
    )

    table.add_row(
        "Lockout Duration", 
        password_policy["lockout_duration"],
        assessment["lockout_duration"]
    )

    console.print(table)