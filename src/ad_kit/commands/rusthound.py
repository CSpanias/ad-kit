"""
RustHound collection command.
"""

import subprocess

from ad_kit.core.console import print_error, print_info, print_success
from ad_kit.core.util import get_artefacts_dir


def run_rusthound(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
) -> bool:
    """
    Collect BloodHound data using RustHound.

    Returns:
        True if collection succeeds, otherwise False.
    """

    output_dir = get_artefacts_dir()

    print_info(f"Running RustHound against {domain} ({dc_ip})...")

    result = subprocess.run(
        [
            "rusthound-ce",
            "-d", domain,
            "-u", username,
            "-p", password,
            "-i", dc_ip,
            "-c", "LdapOnly",
            "-z",
        ],
        cwd=output_dir,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        combined = "\n".join(
            part for part in (result.stdout, result.stderr) if part
        ).lower()

        if (
            "strongerauthrequired" in combined
            or "stronger auth required" in combined
            or "requires binds to turn on integrity checking" in combined
            or "server requires binds to turn on integrity checking" in combined
            or "ldap operation result: rc=8" in combined
        ):
            print_info(
                "RustHound requires LDAP over TLS; retrying with --ldaps..."
            )

            result = subprocess.run(
                [
                    "rusthound-ce",
                    "--ldaps",
                    "-d", domain,
                    "-u", username,
                    "-p", password,
                    "-i", dc_ip,
                    "-c", "LdapOnly",
                    "-z",
                ],
                cwd=output_dir,
                capture_output=True,
                text=True,
            )

    if result.returncode != 0:

        print_error(
            f"RustHound collection failed (exit code {result.returncode})."
        )

        if result.stderr:
            print_error(result.stderr.strip())
        elif result.stdout:
            print_error(result.stdout.strip())

        return False

    print_success("RustHound collection completed.")
    print_info(f"Output directory: {output_dir.resolve()}")

    return True