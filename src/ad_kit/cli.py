"""
Main AD-Kit command-line interface.
"""

import typer

from rich.console import Console
from rich.table import Table

from ad_kit.commands.check import (
    run_checks,
    run_ldap_checks,
    run_smb_checks,
    run_password_policy_checks
)
from ad_kit.commands.enum import run_enumeration
from ad_kit.commands.tools.install import install_tool
from ad_kit.commands.tools.status import show_status
from ad_kit.registry import ToolRegistry

app = typer.Typer(
    add_completion=False,
    name="ad-kit",
    help=("Active Directory Assessment Toolkit."),
    epilog="""
    Examples:

    ad-kit tools install all
    ad-kit tools status

    ad-kit enum

    ad-kit check
    ad-kit check ldap
    ad-kit check smb
    ad-kit check pass-pol
    """,
    no_args_is_help=True,
    context_settings={
        "help_option_names": ["-h", "--help"],
    },
)

# Tools module
tools_app = typer.Typer(help="Manage assessment tools.")
app.add_typer(tools_app, name="tools")


# Check module
check_app = typer.Typer(
    help="Execute assessment checks."
)

app.add_typer(
    check_app,
    name="check",
)

console = Console()

@app.callback()
def main() -> None:
    """
    Active Directory Assessment Toolkit.

    Use the available commands to manage tooling, perform enumeration, and 
    analyse assessment data.
    """

#-------------------------------------------------------------------------------
# TOOLS MODULE
#-------------------------------------------------------------------------------
@tools_app.command(
    name='status',
    help=(
        "Display all tools registered in AD-Kit and their installation source."
    )
)
def tools() -> None:
    """
    List all tools available in the registry.
    """
    registry = ToolRegistry()

    table = Table()

    table.add_column("Name", style="cyan")
    table.add_column("Installer", style="green")
    table.add_column("Description")

    for tool in registry.get_all_tools():
        table.add_row(
            tool.name,
            tool.installer,
            tool.description,
        )

    console.print(table)

#-------------------------------------------------------------------------------
# TOOLS STATUS SUBMODULE
#-------------------------------------------------------------------------------
@tools_app.command(help="Check which registered tools are currently installed.")
def status() -> None:
    """
    Show the installation status of all registered tools.
    """
    show_status()

#-------------------------------------------------------------------------------
# TOOLS INSTALL SUBMODULE
#-------------------------------------------------------------------------------
@tools_app.command(
    help=(
        "Install one or more tools from the AD-Kit registry. "
        "Use 'all' to install every registered tool."
    )
)
def install(
    tool: str = typer.Argument(
        ...,
        help="Tool name or 'all'.",
    ),
) -> None:
    """
    Install a tool defined in the AD-Kit registry.

    The tool name must exist in the registry. The appropriate
    installer implementation will be selected automatically
    based on the tool's configured installer type.

    Args:
        tool: Name of the tool to install.

    Examples:
        ad-kit install netexec
        ad-kit install all
    """
    install_tool(tool)

#-------------------------------------------------------------------------------
# ENUM MODULE
#-------------------------------------------------------------------------------
@app.command(
    help=(
        "Perform basic domain enumeration:\n\n"
        "  • Discover the target domain\n"
        "  • Enumerate domain controllers\n"
        "  • Configure NetExec's audit mode\n"
        "  • Validate a standard user account\n"
        "  • Validate a Domain Admin account\n"
        "  • Create user and machine account lists\n"
        "  • Collect BloodHound data using RustHound-CE\n"
        "  • Dump NTDS using secretsdump"
    )
)

def enum() -> None:
    """
    Perform initial domain and domain controller discovery.

    Examples:
        ad-kit enum
    """
    run_enumeration()

#-------------------------------------------------------------------------------
# CHECK MODULE
#-------------------------------------------------------------------------------
@check_app.callback(
    invoke_without_command=True,
)
def check_callback(
    ctx: typer.Context,
) -> None:
    """
    Execute assessment checks.

    If no specific check module is supplied, all assessment checks are executed.
    """

    if ctx.invoked_subcommand is None:
        run_checks()

#-------------------------------------------------------------------------------
# CHECK ALL MODULE
#-------------------------------------------------------------------------------
@check_app.command(
    name="all",
    help="Execute all assessment checks."
)
def check_all() -> None:
    """
    Execute all assessment checks.
    """

    run_checks()

#-------------------------------------------------------------------------------
# CHECK LDAP MODULE
#-------------------------------------------------------------------------------
@check_app.command(
    name="ldap",
    help="Execute LDAP security checks."
)
def ldap() -> None:
    """
    Execute LDAP signing, channel binding, and
    anonymous bind checks.
    """

    run_ldap_checks()

#-------------------------------------------------------------------------------
# CHECK SMB MODULE
#-------------------------------------------------------------------------------
@check_app.command(
    name="smb",
    help="Execute SMB security checks."
)
def smb() -> None:
    """
    Execute SMB signing and SMBv1 checks.
    """

    run_smb_checks()

#-------------------------------------------------------------------------------
# CHECK PASSWORD POLICY MODULE
#-------------------------------------------------------------------------------
@check_app.command(
    name="pass-pol",
    help="Execute password policy checks."
)
def pass_pol() -> None:
    """
    Execute password policy assessment checks.
    """

    run_password_policy_checks()


if __name__ == "__main__":
    app()