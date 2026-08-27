"""
RustHound collection command.
"""

import subprocess
import typer

from pathlib import Path

from ad_kit.core.console import print_error, print_info, print_success


def run_rusthound(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
) -> None:
    """
    Collect BloodHound data using RustHound.
    """

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