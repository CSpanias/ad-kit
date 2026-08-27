"""
Main AD-Kit command-line interface.
"""

import typer

from rich.console import Console
from rich.table import Table

from ad_kit.commands.dump import run_dump
from ad_kit.commands.enum import run_enumeration
from ad_kit.commands.install import install_tool
from ad_kit.commands.rusthound import run_rusthound
from ad_kit.commands.status import show_status
from ad_kit.registry import ToolRegistry

app = typer.Typer(
    add_completion=False,
    name="ad-kit",
    help=("Active Directory Assessment Toolkit."),
    epilog="""
Examples:
  ad-kit tools
  ad-kit status

  ad-kit install netexec
  ad-kit install all

  ad-kit enum
  ad-kit dump
""",
    no_args_is_help=True,
    context_settings={
        "help_option_names": ["-h", "--help"],
    },
)

console = Console()

@app.callback()
def main() -> None:
    """
    Active Directory Pentest Toolkit Manager.

    Use one of the available commands below to manage
    assessment tooling.
    """

#-------------------------------------------------------------------------------
# tools module
#-------------------------------------------------------------------------------
@app.command(
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
# tools status submodule
#-------------------------------------------------------------------------------
@app.command(help=("Check which registered tools are currently installed."))
def status() -> None:
    """
    Show the installation status of all registered tools.
    """
    show_status()


#-------------------------------------------------------------------------------
# tools install submodule
#-------------------------------------------------------------------------------
@app.command(
    help=(
        "Install one or more tools from the AD-Kit registry. Use 'all' to "
        "install every registered tool."
    )
)
def install(
    tool: str = typer.Argument(
        ...,
        help="Tool name or 'all'."
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
# enum module
#-------------------------------------------------------------------------------
@app.command(
    help=(
        "Perform basic domain enumeration:\n\n"
        "  • Discover the target domain\n"
        "  • Enumerate domain controllers\n"
        "  • Configure NetExec's audit mode\n"
        "  • Validate a standard user account\n"
        "  • Validate a Domain Admin account\n"
        "  • Collect BloodHound data using RustHound-CE"
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
# dump module
#-------------------------------------------------------------------------------
@app.command(help=("Perform an NTDS extraction using Impacket secretsdump."))
def dump() -> None:
    """
    Dump NTDS hashes using a validated Domain Admin account.

    Examples:
        ad-kit dump
    """
    run_dump()


if __name__ == "__main__":
    app()