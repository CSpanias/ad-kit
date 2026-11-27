"""
Main AD-Kit command-line interface.
"""

from importlib.metadata import version

import typer
from rich.console import Console
from rich.table import Table
from typer.core import TyperGroup

from ad_kit.commands import check
from ad_kit.commands.check import AVAILABLE_CHECKS
from ad_kit.commands.enum import run_enumeration
from ad_kit.commands.tools.install import install_tool
from ad_kit.commands.tools.status import show_status
from ad_kit.core.console import print_error
from ad_kit.core.exceptions import ADKitError
from ad_kit.core.preflight import check_preflight, confirm_check_impact
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
        ad-kit check ldap pass-pol
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
class CheckGroup(TyperGroup):
    def parse_args(self, ctx: typer.Context, args: list[str]) -> list[str]:
        exclusions = [
            index for index, arg in enumerate(args)
            if arg == "--exclude" or arg.startswith("--exclude=")
        ]
        if len(exclusions) > 1:
            raise typer.BadParameter("Specify --exclude only once.", param_hint="--exclude")
        if exclusions:
            index = exclusions[0]
            option = args[index]
            names = ([option.split("=", 1)[1]] if "=" in option else []) + args[index + 1:]
            if not names or any(not name.strip() or name.startswith("-") for name in names):
                raise typer.BadParameter(
                    "Specify space-separated check names after --exclude; put other options first.",
                    param_hint="--exclude",
                )
            args = ["--exclude", " ".join(names), *args[:index]]
        return super().parse_args(ctx, args)


check_app = typer.Typer(
    cls=CheckGroup,
    help="Execute all checks or select multiple checks, e.g. 'ad-kit check ldap smb'."
)
app.add_typer(check_app, name="check")

console = Console()

CHECK_ALIASES = {"script-path": "scriptPath"}


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"ad-kit {version('ad-kit')}")
        raise typer.Exit()


@app.callback()
def main(
    show_version: bool = typer.Option(
        False, "--version", callback=_show_version, is_eager=True,
        help="Show the installed version and exit.",
    ),
) -> None:
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
    if not install_tool(tool, force=force):
        raise typer.Exit(code=1)

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
    if not run_enumeration():
        raise typer.Exit(code=1)

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
        None, "--exclude", help="Exclude space-separated checks; place this option last.",
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
            "Specify --exclude only once.", param_hint="--exclude"
        )
    if any(not value.strip() for value in exclude):
        raise typer.BadParameter("Check names cannot be empty.", param_hint="--exclude")
    names = [name for value in exclude for name in value.split()]
    excluded = {CHECK_ALIASES.get(name, name) for name in names}
    unknown = excluded.difference(AVAILABLE_CHECKS)
    if unknown:
        raise typer.BadParameter(
            "Unknown check(s): " + ", ".join(sorted(unknown)), param_hint="--exclude"
        )
    if modules is not None:
        if any(not name.strip() for name in modules):
            raise typer.BadParameter("Check names cannot be empty.", param_hint="MODULES")
        modules = [CHECK_ALIASES.get(name, name) for name in modules]
    remaining = [
        name for name in (modules if modules is not None else AVAILABLE_CHECKS)
        if name not in excluded
    ]
    if not remaining or (excluded and not any(name in AVAILABLE_CHECKS for name in remaining)):
        raise typer.BadParameter("At least one check must remain.", param_hint="--exclude")
    if modules is not None:
        unknown_modules = set(modules).difference(AVAILABLE_CHECKS)
        if unknown_modules:
            raise typer.BadParameter(
                "Unknown check(s): " + ", ".join(sorted(unknown_modules))
                + ". Run 'ad-kit check --help' to see available checks.",
                param_hint="MODULES",
            )
    if modules is not None:
        modules = remaining

    try:
        if csacyber:
            check._export_domain(csacyber)
        check_preflight(remaining)
        if not confirm_check_impact(remaining):
            print_error("Assessment cancelled.")
            raise typer.Exit(code=1)
        with check_workers(workers):
            if csacyber:
                if modules is None:
                    if excluded:
                        success = check.run_checks(csacyber=True, exclude=excluded)
                    else:
                        success = check.run_checks(csacyber=True)
                else:
                    success = check.run_selected_checks(modules, csacyber=True)
            elif modules is None:
                if excluded:
                    success = check.run_checks(exclude=excluded)
                else:
                    success = check.run_checks()
            else:
                success = check.run_selected_checks(modules)
    except typer.Exit:
        raise
    except (ADKitError, ValueError, RuntimeError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    if not success:
        raise typer.Exit(code=1)


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
        None, "--exclude", help="Exclude space-separated checks; place this option last.",
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
        modules: list[str] | None = typer.Argument(
            None, help="Additional check names to execute in order."
        ),
        csacyber: bool = typer.Option(
            False, "--csacyber", help="Export SureFormat XML instead of JSON."
        ),
        workers: int | None = typer.Option(
            None, "--workers", min=1, max=16,
            help="Parallel check workers (1-16; default: 4).",
        ),
        exclude: list[str] | None = typer.Option(
            None, "--exclude", help="Exclude space-separated checks; place this option last.",
        ),
    ) -> None:
        _run_check_command(
            [module_name, *(modules or [])],
            *_check_options(ctx, csacyber, workers, exclude),
        )

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

check_app.command(
    name="script-path",
    help="Execute user logon script path checks (alias for scriptPath).",
)(_make_check_command("scriptPath"))


if __name__ == "__main__":
    app()