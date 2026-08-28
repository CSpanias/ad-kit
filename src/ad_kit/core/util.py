import json
import typer

from pathlib import Path

from console import console, print_section

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
        "SSH Host",
        default=session_data.get("jumpbox_host", ""),
        show_default=False,
    )

    user = typer.prompt(
        "SSH Username",
        default=session_data.get("jumpbox_user", ""),
        show_default=False,
    )

    ssh_key = typer.prompt(
        "SSH Key Path",
        default=session_data.get("ssh_key", ""),
        show_default=False,
    )

    session_data["jumpbox_host"] = host
    session_data["jumpbox_user"] = user
    session_data["ssh_key"] = ssh_key

    save_session(session_data)

    artefacts_dir = get_artefacts_dir()

    command = (
        f'scp -i "{ssh_key}" '
        f'"{user}@{host}:{artefacts_dir.resolve()}/*" '
        f'./'
    )

    console.print()
    console.print(command, style="cyan")
    console.print()