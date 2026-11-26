"""
Main AD-Kit command-line interface.
"""

import typer
from rich.console import Console
from rich.table import Table

from ad_kit.commands import check
from ad_kit.commands.check import AVAILABLE_CHECKS
from ad_kit.commands.enum import run_enumeration
from ad_kit.commands.tools.install import install_tool
from ad_kit.commands.tools.status import show_status
from ad_kit.core.util import check_workers
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
    force: bool = typer.Option(
        False,
        "--force",
        help="Reinstall even when a tool is already on PATH.",
    ),
) -> None:
    """
    Install a tool defined in the ad-kit registry.

    The tool name must exist in the registry. The appropriate
    installer implementation will be selected automatically
    based on the tool's configured installer type.

    Args:
        tool: Name of the tool to install.
        force: Reinstall already installed tools.

    Examples:
        ad-kit tools install netexec
        ad-kit tools install all
    """
    install_tool(tool, force=force)

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
    csacyber: bool = typer.Option(
        False, "--csacyber", help="Export SureFormat XML instead of JSON."
    ),
    workers: int | None = typer.Option(
        None, "--workers", min=1, max=16,
        help="Parallel check workers (1-16; default: 4).",
    ),
    exclude: list[str] | None = typer.Option(
        None, "--exclude", help="Exclude checks using a comma-separated list of names.",
    ),
) -> None:
    """
    Execute assessment checks.

    If no specific check module is supplied, all assessment checks are executed.
    """

    ctx.obj = (csacyber, workers, exclude or [])
    if ctx.invoked_subcommand is None:
        _run_check_command(None, csacyber, workers or 4, exclude or [])


def _run_check_command(
    modules: list[str] | None, csacyber: bool, workers: int,
    exclude: list[str],
) -> None:
    if len(exclude) > 1:
        raise typer.BadParameter(
            "Specify --exclude once with comma-separated check names.", param_hint="--exclude"
        )
    names = [name.strip() for value in exclude for name in value.split(",")]
    if any(not name for name in names):
        raise typer.BadParameter("Check names cannot be empty.", param_hint="--exclude")
    excluded = set(names)
    unknown = excluded.difference(AVAILABLE_CHECKS)
    if unknown:
        raise typer.BadParameter(
            "Unknown check(s): " + ", ".join(sorted(unknown)), param_hint="--exclude"
        )
    remaining = [
        name for name in (modules if modules is not None else AVAILABLE_CHECKS)
        if name not in excluded
    ]
    if not remaining or (excluded and not any(name in AVAILABLE_CHECKS for name in remaining)):
        raise typer.BadParameter("At least one check must remain.", param_hint="--exclude")
    if modules is not None:
        modules = remaining

    with check_workers(workers):
        if csacyber:
            try:
                check._export_domain(csacyber)
            except (ValueError, RuntimeError) as exc:
                raise typer.BadParameter(str(exc)) from exc
            if modules is None:
                if excluded:
                    check.run_checks(csacyber=True, exclude=excluded)
                else:
                    check.run_checks(csacyber=True)
            else:
                check.run_selected_checks(modules, csacyber=True)
        elif modules is None:
            if excluded:
                check.run_checks(exclude=excluded)
            else:
                check.run_checks()
        else:
            check.run_selected_checks(modules)


def _check_options(
    ctx: typer.Context, csacyber: bool, workers: int | None,
    exclude: list[str] | None,
) -> tuple[bool, int, list[str]]:
    parent_csacyber, parent_workers, parent_exclude = ctx.parent.obj
    if workers is not None and parent_workers is not None:
        raise typer.BadParameter("Specify --workers only once.")
    return (
        csacyber or parent_csacyber,
        workers if workers is not None else parent_workers or 4,
        parent_exclude + (exclude or []),
    )

#-------------------------------------------------------------------------------
# CHECK ALL MODULE
#-------------------------------------------------------------------------------
@check_app.command(
    name="all",
    help="Execute all assessment checks."
)
def check_all(
    ctx: typer.Context,
    csacyber: bool = typer.Option(
        False, "--csacyber", help="Export SureFormat XML instead of JSON."
    ),
    workers: int | None = typer.Option(
        None, "--workers", min=1, max=16,
        help="Parallel check workers (1-16; default: 4).",
    ),
    exclude: list[str] | None = typer.Option(
        None, "--exclude", help="Exclude checks using a comma-separated list of names.",
    ),
) -> None:
    """
    Execute all assessment checks.
    """

    _run_check_command(None, *_check_options(ctx, csacyber, workers, exclude))

#-------------------------------------------------------------------------------
# CHECK COMMANDS (generated dynamically from AVAILABLE_CHECKS)
#-------------------------------------------------------------------------------


def _make_check_command(module_name: str):
    """Factory that creates a check command for the given module name."""

    def run_check(
        ctx: typer.Context,
        csacyber: bool = typer.Option(
            False, "--csacyber", help="Export SureFormat XML instead of JSON."
        ),
        workers: int | None = typer.Option(
            None, "--workers", min=1, max=16,
            help="Parallel check workers (1-16; default: 4).",
        ),
        exclude: list[str] | None = typer.Option(
            None, "--exclude", help="Exclude checks using a comma-separated list of names.",
        ),
    ) -> None:
        _run_check_command([module_name], *_check_options(ctx, csacyber, workers, exclude))

    run_check.__name__ = (
        f"check_{module_name.replace('-', '_').replace('.', '_')}"
    )
    run_check.__doc__ = f"Execute {module_name} assessment checks."
    return run_check


for _module_name in AVAILABLE_CHECKS:

    check_app.command(
        name=_module_name,
        help=f"Execute {_module_name} assessment checks.",
    )(_make_check_command(_module_name))


#-------------------------------------------------------------------------------
# CHECK SELECTED
#-------------------------------------------------------------------------------
@check_app.command(
    name="run",
    help="Execute comma- or space-separated assessment modules.",
)
def selected(
    ctx: typer.Context,
    modules: list[str],
    csacyber: bool = typer.Option(
        False, "--csacyber", help="Export SureFormat XML instead of JSON."
    ),
    workers: int | None = typer.Option(
        None, "--workers", min=1, max=16,
        help="Parallel check workers (1-16; default: 4).",
    ),
    exclude: list[str] | None = typer.Option(
        None, "--exclude", help="Exclude checks using a comma-separated list of names.",
    ),
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

    groups = " ".join(modules).split(",")
    if any(not group.strip() for group in groups):
        raise typer.BadParameter("Check names cannot be empty.", param_hint="MODULES")
    names = [name for group in groups for name in group.split()]
    _run_check_command(names, *_check_options(ctx, csacyber, workers, exclude))


if __name__ == "__main__":
    app()