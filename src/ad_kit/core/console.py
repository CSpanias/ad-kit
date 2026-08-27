"""
Console helpers for AD-Kit.

Provides consistent Rich-based output across the application.
"""

from rich.console import Console

console = Console()

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
    console.print(f"\n[bold cyan][ {title} ][/bold cyan]\n")