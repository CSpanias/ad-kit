"""
Main AD-Kit command-line interface.
"""

import typer

from rich.console import Console
from rich.table import Table

from ad_kit.commands import check
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
        ad-kit tools install certipy
        ad-kit tools status

        ad-kit enum

        ad-kit check all
        ad-kit check ldap
        ad-kit check run ldap pass-pol
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
check_app = typer.Typer(help="Execute assessment checks.")
app.add_typer(check_app, name="check")

console = Console()

@app.callback()
def main() -> None:
    """
    ad-kit command-line interface entrypoint.

    Use the available commands to manage assessment tooling, perform Active
    Directory enumeration, and execute assessment checks.
    """

#-------------------------------------------------------------------------------
# TOOLS COMMANDS
#-------------------------------------------------------------------------------
@tools_app.command(
    name="status",
    help=(
        "Display all tools registered in ad-kit and their installation source."
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
        "Install one or more tools from the ad-kit registry. Use 'all' to "
        "install every registered tool."
    )
)
def install(
    tool: str = typer.Argument(
        ...,
        help="Tool name or 'all'.",
    ),
) -> None:
    """
    Install a tool defined in the ad-kit registry.

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
# ENUM COMMANDS
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

    Bootstrap an Active Directory assessment.

    This command identifies the target domain, enumerates Domain Controllers,
    validates credentials, exports user and computer information, performs
    BloodHound collection, and dumps NTDS secrets.

    Examples:
        ad-kit enum
    """
    run_enumeration()

#-------------------------------------------------------------------------------
# CHECK COMMANDS
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
        check.run_checks()

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

    check.run_checks()

#-------------------------------------------------------------------------------
# CHECK LDAP MODULE
#-------------------------------------------------------------------------------
@check_app.command(
    name="ldap",
    help="Execute LDAP security checks."
)
def ldap() -> None:
    """
    Execute LDAP security checks.

    This command evaluates LDAP signing, channel binding enforcement, and
    anonymous LDAP bind configuration across all discovered Domain Controllers.
    """

    check.run_ldap_checks()

#-------------------------------------------------------------------------------
# CHECK SMB MODULE
#-------------------------------------------------------------------------------
@check_app.command(
    name="smb",
    help="Execute SMB security checks."
)
def smb() -> None:
    """
    Execute SMB security checks.

    This command evaluates SMB signing requirements and SMBv1 support across 
    discovered hosts and Domain Controllers.
    """

    check.run_smb_checks()

#-------------------------------------------------------------------------------
# CHECK AS-REP ROASTING
#-------------------------------------------------------------------------------

@check_app.command(
    name="asreproast",
    help="Identify accounts susceptible to AS-REP roasting.",
)
def asreproast() -> None:
    """
    Execute AS-REP roasting assessment checks.
    """

    check.run_asreproast_checks()

#-------------------------------------------------------------------------------
# CHECK PASSWORD POLICY MODULE
#-------------------------------------------------------------------------------
@check_app.command(
    name="pass-pol",
    help="Execute password policy checks."
)
def pass_pol() -> None:
    """
    Execute domain password policy checks.

    This command retrieves and assesses the effective Active Directory password 
    policy against common security best practices.
    """

    check.run_password_policy_checks()

#-------------------------------------------------------------------------------
# CHECK MAQ
#-------------------------------------------------------------------------------
@check_app.command(
    name="maq",
    help="Execute Machine Account Quota check."
)
def run_maq_checks() -> None:
    """
    Execute Machine Account Quota assessment checks.

    This check retrieves the Active Directory Machine Account Quota 
    configuration and determines whether authenticated users are permitted to 
    create machine accounts within the domain.

    Findings are generated when a non-zero Machine Account Quota is identified.
    """

    check.run_maq_checks()

#-------------------------------------------------------------------------------
# CHECK DNS
#-------------------------------------------------------------------------------
@check_app.command(
    name="dns",
    help="Execute DNS permission check.",
)
def dns() -> None:
    """
    Execute DNS permission assessment checks.
    """

    check.run_dns_checks()

#-------------------------------------------------------------------------------
# CHECK PRE-WINDOWS 2000 COMPUTER ACCOUNTS
#-------------------------------------------------------------------------------
@check_app.command(
    name="pre2k",
    help=(
        "Identify pre-created computer accounts susceptible to the pre-Windows "
        "2000 password convention."
    ),
)
def pre2k() -> None:
    """
    Execute pre-Windows 2000 computer account assessment checks.
    """

    check.run_pre2k_checks()

#-------------------------------------------------------------------------------
# CHECK PRIVILEGED GROUPS
#-------------------------------------------------------------------------------
@check_app.command(
    name="privileged",
    help="Review privileged Active Directory group membership.",
)
def privileged() -> None:
    """
    Execute privileged group membership assessment checks.
    """

    check.run_privileged_group_checks()

#-------------------------------------------------------------------------------
# CHECK DELEGATION
#-------------------------------------------------------------------------------

@check_app.command(
    name="delegation",
    help="Review Active Directory delegation configuration.",
)
def delegation() -> None:
    """
    Execute Active Directory delegation assessment checks.
    """

    check.run_delegation_checks()

#-------------------------------------------------------------------------------
# CHECK KERBEROASTING
#-------------------------------------------------------------------------------

@check_app.command(
    name="kerberoast",
    help="Identify Kerberoastable accounts.",
)
def kerberoast() -> None:
    """
    Execute Kerberoasting assessment checks.
    """

    check.run_kerberoast_checks()

#-------------------------------------------------------------------------------
# CHECK ACTIVE DIRECTORY CERTIFICATE SERVICES
#-------------------------------------------------------------------------------

@check_app.command(
    name="adcs",
    help=("Review Active Directory Certificate Services (AD CS) configuration."
    ),
)
def adcs() -> None:
    """
    Execute Active Directory Certificate Services (AD CS) assessment checks.
    """

    check.run_adcs_checks()

#-------------------------------------------------------------------------------
# CHECK SELECTED
#-------------------------------------------------------------------------------
@check_app.command(
    name="run",
    help="Execute selected assessment modules.",
)
def selected(
    modules: list[str],
) -> None:
    """
    Execute one or more specified assessment modules.

    Modules are executed in the order provided on the command line, allowing 
    targeted assessment of specific Active Directory security controls without 
    running the full assessment workflow.

    Args:
        modules:
            Assessment modules to execute.
    """

    check.run_selected_checks(modules)


if __name__ == "__main__":
    app()