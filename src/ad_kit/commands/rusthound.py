"""
RustHound collection command.
"""

import subprocess
import typer

from pathlib import Path

from ad_kit.core.console import print_error, print_info, print_success


def run_rusthound() -> None:
    """
    Collect BloodHound data using RustHound.
    """

    try:
        domain = Path("domain.txt").read_text(encoding="utf-8").strip()
        dc_ip = Path("dc-ips.txt").read_text(encoding="utf-8").splitlines()[0]

    except FileNotFoundError:
        print_error("Enumeration files not found. Run 'ad-kit enum' first.")
        return

    username = typer.prompt("Username")
    password = typer.prompt("Password",hide_input=True)

    output_dir = Path("bloodhound")
    output_dir.mkdir(exist_ok=True)

    print_info(f"Running RustHound against {domain} ({dc_ip})...")

    result = subprocess.run(
        [
            "rusthound-ce",
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "-i",
            dc_ip,
            "-z",
        ],
        cwd=output_dir,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print_error("RustHound collection failed.")

        if result.stderr:
            print_error(result.stderr.strip())

        return

    print_success("RustHound collection completed.")
    print_info(f"Output directory: {output_dir.resolve()}")