"""
Status command implementation.

This module provides functionality for checking whether tools
defined in the registry are installed and available in the
current user's PATH.
"""

from shutil import which

from rich.console import Console
from rich.table import Table

from ad_kit.registry import ToolRegistry

console = Console()


def show_status() -> None:
    """
    Display the installation status of all registered tools.

    A tool is considered installed if its executable can be found
    in the current PATH.

    Returns:
        None
    """
    registry = ToolRegistry()

    table = Table()

    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Executable Path", style="dim")

    installed_count = 0
    missing_count = 0

    for tool in registry.get_all_tools():
        executable_path = which(tool.check_command)

        if executable_path:
            status = "[green]✓ Installed[/green]"
            installed_count += 1
        else:
            status = "[red]✗ Missing[/red]"
            executable_path = "-"
            missing_count += 1

        table.add_row(
            tool.name,
            status,
            executable_path,
        )

    console.print(table)

    console.print(
        f"\n[green]Installed:[/green] {installed_count} | "
        f"[red]Missing:[/red] {missing_count}"
    )