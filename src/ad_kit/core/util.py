import json
import typer

from contextlib import contextmanager
from pathlib import Path

from ad_kit.core.console import console, print_section, print_info

ARTEFACTS_DIR = Path("ad-kit")


def get_artefacts_dir() -> Path:
    """
    Return the AD-Kit artefacts directory.
    """

    ARTEFACTS_DIR.mkdir(exist_ok=True,)

    return ARTEFACTS_DIR


def get_session_file() -> Path:
    """
    Return the AD-Kit session file.
    """

    return (get_artefacts_dir() / "session.json")


def load_session() -> dict:
    session_file = get_session_file()

    if not session_file.exists():
        raise RuntimeError("Session metadata not found.")

    return json.loads(session_file.read_text(encoding="utf-8"))


def save_session(
    session_data: dict,
) -> None:
    get_session_file().write_text(
        json.dumps(session_data, indent=4),
        encoding="utf-8",
    )


def generate_scp_command(
    session_data: dict,
) -> None:
    """
    Generate an SCP retrieval command.
    """

    print_section("Retrieval")

    host = typer.prompt(
        "SSH Host's IP Address (typically the Tailscale IP)",
        default=session_data.get("jumpbox_host", ""),
        show_default=False,
    )

    user = typer.prompt(
        "SSH Username (typically x-user)",
        default=session_data.get("jumpbox_user", ""),
        show_default=False,
    )

    remote_dir = typer.prompt(
        "Remote AD-Kit Directory (typically /home/x-user/ad-kit)",
        default=session_data.get("remote_dir", ""),
        show_default=False,
    )

    session_data["jumpbox_host"] = host
    session_data["jumpbox_user"] = user
    session_data["remote_dir"] = remote_dir

    save_session(session_data)

    command = (
        f'scp '
        f'"{user}@{host}:{remote_dir}/*.zip" '
        f'"{user}@{host}:{remote_dir}/*.ntds*" '
        './'
    )

    console.print()
    print_info(
        "From your local Kali VM, execute the following command to retrieve "
        "the assessment artefacts:"
    )
    console.print()
    console.print(command, style="cyan")
    console.print()


@contextmanager
def progress(
    message: str,
):
    """
    Display a spinner while a task is running.
    """

    with console.status(f"[cyan]{message}"):
        yield


def normalize_hostname(
    hostname: str,
) -> str:
    """
    Normalize a hostname/FQDN for display.

    Args:
        hostname: Hostname or FQDN.

    Returns:
        Normalized FQDN.
    """

    return hostname.upper()