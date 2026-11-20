import getpass
import ipaddress
import json
import os
import shlex
import subprocess
from contextlib import contextmanager
from pathlib import Path

import typer

from ad_kit.core.console import console, print_info, print_section, print_warning
from ad_kit.core.exceptions import ADKitError

ARTEFACTS_DIR = Path("ad-kit")


def require_collected_data(session_data: dict, key: str, label: str) -> None:
    if session_data.get(key) is not True:
        raise ADKitError(
            f"{label} collection was not completed for this session. "
            "Run 'ad-kit enum' again before using this check."
        )


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
    files: list[Path],
) -> None:
    """Generate an SCP command for artefacts collected in this run."""

    print_section("Retrieval")

    if not files:
        print_warning("No BloodHound ZIP or NTDS files were collected in this run.")
        return

    try:
        result = subprocess.run(
            ["ip", "-j", "address", "show"],
            capture_output=True,
            text=True,
            check=True,
        )
        interfaces = json.loads(result.stdout)
        addresses = []
        for interface in interfaces:
            if "UP" not in interface["flags"]:
                continue
            for entry in interface["addr_info"]:
                if entry["family"] not in ("inet", "inet6"):
                    continue
                address = ipaddress.ip_address(entry["local"])
                if address.is_loopback or address.is_link_local or address.is_unspecified:
                    continue
                addresses.append((interface["ifname"], str(address)))
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError, TypeError) as exc:
        print_warning(f"Unable to identify network interfaces: {exc}")
        return

    if not addresses:
        print_warning("No usable network interface addresses were found.")
        return

    print_info("Select an address reachable from your local machine:")
    for index, (interface, address) in enumerate(addresses, 1):
        console.print(f"  {index}. {interface}: {address}")
    while True:
        selection = typer.prompt("Interface address number", type=int)
        if 1 <= selection <= len(addresses):
            break
        print_warning(f"Choose a number between 1 and {len(addresses)}.")

    address = addresses[selection - 1][1]
    host = f"[{address}]" if ":" in address else address
    try:
        if os.name == "posix":
            import pwd

            username = pwd.getpwuid(os.geteuid()).pw_name
        else:
            username = getpass.getuser()
    except (KeyError, OSError) as exc:
        print_warning(f"Unable to identify the current OS user: {exc}")
        return
    sources = [
        f"{username}@{host}:{path.resolve()}"
        for path in files
    ]
    command = shlex.join(["scp", *sources, "./"])

    console.print()
    print_info(
        "From your local Kali VM, execute the following command to retrieve "
        "the assessment artefacts:"
    )
    console.print()
    console.print(command, style="cyan", markup=False)
    console.print()
    print_info(
        "The SSH username is the current OS user; adjust it if you connect "
        "using a different account."
    )


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


def require_session() -> dict:
    """
    Load session metadata required by assessment
    modules.

    Returns:
        Parsed session metadata.

    Raises:
        RuntimeError:
            If assessment session metadata is not
            available.
    """

    try:

        return load_session()

    except RuntimeError as exc:

        raise RuntimeError(
            "Assessment session metadata not found. Run 'ad-kit enum' before "
            "executing assessment checks."
        ) from exc