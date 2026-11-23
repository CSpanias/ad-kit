from rich.table import Table

from ad_kit.checks.nopac import nopac_check
from ad_kit.checks.scriptpath import scriptpath_check
from ad_kit.core.checks import get_evidence_dir
from ad_kit.core.console import console, print_info, print_section
from ad_kit.core.util import progress, require_session
from ad_kit.reporting.results import record_findings, record_incomplete

from .credentials import authenticate_standard_user


def run_nopac_checks(
    std_pass: str | None = None,
) -> None:
    """
    Assess discovered Domain Controllers for NoPAC vulnerability indicators.
    """

    session_data = require_session()
    standard_user = session_data.get("standard_user", "")
    if not standard_user:
        print_info(
            "Skipping NoPAC check: no Standard User is configured for this "
            "session."
        )
        return

    if std_pass is None:
        std_pass = authenticate_standard_user()

    dc_ips = sorted(set(session_data.get("dc_ips") or [session_data["dc_ip"]]))

    print_section("NoPAC Check")

    with progress("Checking discovered Domain Controllers for NoPAC..."):
        results, findings = nopac_check(
            dc_ips,
            standard_user,
            std_pass,
        )

    table = Table(title="NoPAC Assessment")
    table.add_column("Domain Controller", style="cyan")
    table.add_column("TGT with PAC (bytes)", style="green")
    table.add_column("TGT without PAC (bytes)", style="green")
    table.add_column("Assessment", style="yellow")

    for result in results:
        status_style = (
            "red"
            if result["status"] == "Vulnerable"
            else "green"
            if result["status"] == "Not vulnerable"
            else "yellow"
        )
        table.add_row(
            result["dc_ip"],
            (
                str(result["with_pac_size"])
                if result["with_pac_size"] is not None
                else "N/A"
            ),
            (
                str(result["without_pac_size"])
                if result["without_pac_size"] is not None
                else "N/A"
            ),
            f"[{status_style}]{result['status']}[/{status_style}]",
        )

    console.print(table)
    record_findings(findings)

def run_scriptpath_checks(
    std_pass: str | None = None,
) -> None:
    """Review user logon script paths and Standard User write access."""

    session_data = require_session()
    standard_user = session_data.get("standard_user", "")
    if not standard_user:
        print_info(
            "Skipping script-path checks: no Standard User is configured "
            "for this session."
        )
        return

    if std_pass is None:
        std_pass = authenticate_standard_user()

    dc_ips = sorted(set(session_data.get("dc_ips") or [session_data["dc_ip"]]))
    dc_hostnames = session_data.get("dc_hostnames", [])

    print_section("User Logon Script Paths")

    with progress("Enumerating user logon script paths and permissions..."):
        results, findings = scriptpath_check(
            session_data["dc_ip"],
            dc_ips,
            dc_hostnames,
            session_data["domain"],
            standard_user,
            std_pass,
        )

    table = Table(title="User Logon Script Paths")
    table.add_column("User", style="cyan")
    table.add_column("ScriptPath", style="green")
    table.add_column("Resolved Path", style="yellow")
    table.add_column("Standard User Write", style="red")
    table.add_column("Notes", style="white")

    if results:
        for result in results:
            write_access = result["standard_user_writable"]
            status_style = (
                "red"
                if write_access == "Yes"
                else "green"
                if write_access == "No"
                else "yellow"
            )
            table.add_row(
                result["username"],
                result["script_path"],
                result["resolved_path"],
                f"[{status_style}]{write_access}[/{status_style}]",
                result["error"] or "",
            )
    else:
        table.add_row(
            "No scriptPath values found",
            "",
            "",
            "N/A",
            "",
        )

    console.print(table)

    evidence_lines: list[str] = []
    incomplete_paths: set[tuple[str, str]] = set()
    for result in results:
        if result["error"]:
            incomplete_paths.add((result["resolved_path"], result["error"]))
        evidence_lines.extend(
            [
                f"User: {result['username']}",
                f"ScriptPath: {result['script_path']}",
                f"Resolved Path: {result['resolved_path']}",
                (
                    "Standard User Write Access: "
                    f"{result['standard_user_writable']}"
                ),
                f"ACL Entries: {'; '.join(result['acl_entries']) or 'Unavailable'}",
                f"Notes: {result['error'] or 'None'}",
                "",
            ]
        )
    (get_evidence_dir() / "scriptpath-permissions.txt").write_text(
        "\n".join(evidence_lines),
        encoding="utf-8",
    )

    for path, error in sorted(incomplete_paths):
        record_incomplete("scriptPath", path, error, notify=False)

    record_findings(findings)
