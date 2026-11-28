"""
Console helpers for AD-Kit.

Provides consistent Rich-based output across the application.
"""

from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def object_text(objects: list[str]) -> Text:
    return Text("\n".join(objects) if objects else "-")


def account_group_table(
    accounts: list[str],
    groups: dict[str, list[str]] | None,
    *,
    account_heading: str = "Account",
    status: str | None = None,
) -> Table:
    table = Table()
    table.add_column(account_heading, style="cyan")
    if status is not None:
        table.add_column("Status", style="yellow")
    show_groups = groups is None or bool(groups)
    if show_groups:
        table.add_column("Privileged Group", style="yellow")
    for account in accounts:
        row = [Text(account)]
        if status is not None:
            row.append(Text(status))
        if show_groups:
            row.append(Text("Unknown" if groups is None else "\n".join(
                groups.get(account.casefold(), [])
            ) or "-"))
        table.add_row(*row)
    if not accounts:
        row = [Text("None found")]
        if status is not None:
            row.append(Text("✓ OK", style="green"))
        if show_groups:
            row.append(Text("-"))
        table.add_row(*row)
    return table


def print_info(message: str) -> None:
    """
    Display an informational message.

    Args:
        message: Message to display.
    """
    console.print(f"[cyan][*][/cyan] {message}")


def print_success(message: str) -> None:
    """
    Display a success message.

    Args:
        message: Message to display.
    """
    console.print(f"[green][+][/green] {message}")


def print_warning(message: str) -> None:
    """
    Display a warning message.

    Args:
        message: Message to display.
    """
    console.print(f"[yellow][!][/yellow] {message}")


def print_error(message: str) -> None:
    """
    Display an error message.

    Args:
        message: Message to display.
    """
    console.print(f"[red][-][/red] {message}")


def print_section(title: str) -> None:
    console.print(f"\n[bold cyan][{title}][/bold cyan]\n")