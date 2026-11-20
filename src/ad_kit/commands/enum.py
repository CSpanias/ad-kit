"""
Initial engagement enumeration functionality.
"""

import re
import subprocess
import tempfile
from pathlib import Path

import typer
from rich.table import Table

from ad_kit.commands.rusthound import run_rusthound
from ad_kit.core.console import (
    console, print_error, print_info, print_section, print_success, print_warning,
)
from ad_kit.core.util import generate_scp_command, get_artefacts_dir, progress, save_session


def _artefact_snapshot(output_dir: Path, pattern: str) -> dict[Path, tuple[int, int, int]]:
    """Track file metadata to identify outputs created or replaced by a command."""
    snapshot = {}
    for path in output_dir.glob(pattern):
        if path.is_file():
            stat = path.stat()
            snapshot[path] = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
    return snapshot


def _new_artefacts(
    output_dir: Path, pattern: str, before: dict[Path, tuple[int, int, int]]
) -> list[Path]:
    after = _artefact_snapshot(output_dir, pattern)
    return sorted(path for path, state in after.items() if before.get(path) != state)


def _dump_ntds(
    domain: str,
    username: str,
    password: str,
    dc_ips: list[str],
    output_dir: Path,
) -> tuple[Path, str] | None:
    """Try each DC with an isolated secretsdump output directory."""
    record = re.compile(
        r"[^:\r\n]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::"
        r"(?:\s+\(status=(?:Enabled|Disabled|N/A)\))?",
        re.IGNORECASE,
    )
    auth_errors = (
        "STATUS_LOGON_FAILURE", "STATUS_WRONG_PASSWORD", "STATUS_ACCOUNT_LOCKED_OUT",
        "STATUS_ACCOUNT_DISABLED", "STATUS_ACCOUNT_RESTRICTION", "STATUS_PASSWORD_EXPIRED",
        "STATUS_PASSWORD_MUST_CHANGE", "STATUS_NO_SUCH_USER", "KDC_ERR_PREAUTH_FAILED",
        "KDC_ERR_CLIENT_REVOKED", "KDC_ERR_C_PRINCIPAL_UNKNOWN", "LOGON FAILURE",
        "ACCOUNT LOCKED",
    )

    for dc_ip in dict.fromkeys(dc_ips):
        print_info(f"Attempting NTDS dump from {dc_ip}.")
        with tempfile.TemporaryDirectory(dir=output_dir.resolve(), prefix=".ntds-") as directory:
            attempt_dir = Path(directory)
            try:
                with progress("[cyan]Running secretsdump..."):
                    result = subprocess.run(
                        [
                            "secretsdump.py",
                            f"{domain}/{username}:{password}@{dc_ip}",
                            "-user-status",
                            "-just-dc-ntlm",
                            "-outputfile",
                            domain,
                        ],
                        cwd=attempt_dir,
                        capture_output=True,
                        text=True,
                    )
            except OSError as exc:
                print_error(f"Unable to start secretsdump: {exc}")
                return None

            output = result.stdout + "\n" + result.stderr
            diagnostics = [
                line.strip() for line in output.splitlines()
                if re.match(r"^\s*(?:\[-\]|\[!\]|ERROR:|CRITICAL:)", line, re.IGNORECASE)
            ]
            if not diagnostics and result.returncode and result.stderr.strip():
                diagnostics = [result.stderr.strip().splitlines()[-1]]
            attempt_file = attempt_dir / f"{domain}.ntds"
            valid_records = False
            if attempt_file.is_file():
                try:
                    with attempt_file.open(encoding="utf-8") as dump:
                        for line in dump:
                            line = line.strip()
                            if not line:
                                continue
                            if not record.fullmatch(line):
                                valid_records = False
                                break
                            valid_records = True
                except (OSError, UnicodeError) as exc:
                    print_warning(f"Unable to read NTDS dump from {dc_ip}: {exc}")
                    valid_records = False

            incomplete = any(attempt_dir.glob("sessionresume_*"))
            if result.returncode == 0 and not diagnostics and not incomplete and valid_records:
                destination = output_dir / attempt_file.name
                attempt_file.replace(destination)
                return destination, dc_ip

            print_warning(f"NTDS dump from {dc_ip} did not complete.")
            if diagnostics:
                for line in diagnostics:
                    if password:
                        line = line.replace(password, "[REDACTED]")
                    line = re.sub(r"\b[0-9a-f]{32}\b", "[REDACTED]", line, flags=re.IGNORECASE)
                    print_warning(line)
            elif result.returncode:
                print_warning(f"secretsdump exited with code {result.returncode}.")
            elif incomplete:
                print_warning("secretsdump left an incomplete resume file.")
            else:
                print_warning("No valid NTDS hash records were produced.")

            if any(error in output.upper() for error in auth_errors):
                print_error("Authentication failure detected; not trying additional DCs.")
                return None

    return None


# TODO: Automate domain and DC resolution
def identify_domain_controller(
    dc_ip: str,
) -> tuple[str, str]:
    """
    Identify a Domain Controller and its domain
    from an IP address.

    Args:
        dc_ip: Domain Controller IP address.

    Returns:
        A tuple containing:
        - Fully qualified Domain Controller hostname.
        - Active Directory domain name.

    Raises:
        RuntimeError: If the Domain Controller
            hostname or domain cannot be identified.
    """

    result = subprocess.run(
        ["nxc", "ldap", dc_ip],
        capture_output=True,
        text=True,
        check=False,
    )

    output = result.stdout
    name_match = re.search(r"\(name:([^)]+)\)", output)
    domain_match = re.search(r"\(domain:([^)]+)\)", output)

    if not name_match or not domain_match:
        raise RuntimeError("Failed to identify the Domain Controller.")

    hostname = name_match.group(1).upper()
    domain = domain_match.group(1).upper()

    return hostname, domain


def write_results(
    domain: str,
    dc_hostnames: list[str],
    dc_ips: list[str],
) -> None:
    """
    Write discovery results to files.

    Args:
        domain: Domain name.
        dc_hostnames: DC hostnames.
        dc_ips: DC IP addresses.
    """

    artefacts_dir = get_artefacts_dir()

    (artefacts_dir / "domain.txt").write_text(
        f"{domain}\n".upper(), 
        encoding="utf-8"
    )

    dc_hostnames = sorted(dc_hostnames)

    (artefacts_dir / "dc-hostnames.txt").write_text(
        "\n".join(dc_hostnames).upper() + "\n",
        encoding="utf-8",
    )

    dc_ips = sorted(dc_ips)

    (artefacts_dir / "dc-ips.txt").write_text(
        "\n".join(dc_ips) + "\n",
        encoding="utf-8",
    )


def configure_nxc() -> None:
    """
    Ensure NetExec audit mode is enabled.
    """

    nxc_config = Path.home() / ".nxc" / "nxc.conf"

    if not nxc_config.exists():
        subprocess.run(
            ["netexec", "--help"],
            capture_output=True,
            text=True,
        )

    if not nxc_config.exists():
        print_info(
            "NetExec configuration not found. Run NetExec once to generate it."
        )
        return

    content = nxc_config.read_text(encoding="utf-8")

    if "audit_mode = *" in content:
        print_success("NetExec audit mode already configured.")
        return

    updated = []
    audit_mode_found = False

    for line in content.splitlines():
        if line.startswith("audit_mode"):
            updated.append("audit_mode = *")
            audit_mode_found = True
        else:
            updated.append(line)

    if not audit_mode_found:
        updated.append("audit_mode = *")

    nxc_config.write_text("\n".join(updated) + "\n", encoding="utf-8")

    print_success("NetExec audit mode configured.")


def validate_credentials(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[bool, bool]:
    """
    Validate credentials and NetExec's privilege marker using LDAP.

    Returns:
        (
            authentication_successful,
            privileged_access,
        )
    """
    result = subprocess.run(
        [
            "nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"LDAP credential validation failed (NetExec exit code {result.returncode})."
        )

    account = username.rsplit("\\", 1)[-1].lower()
    for line in result.stdout.splitlines():
        if f"\\{account}:" not in line.lower():
            continue
        if "[+]" in line:
            return (True, "Pwn3d!" in line)
        if "[-]" in line:
            return (False, False)

    raise RuntimeError("Unable to determine the LDAP credential validation result.")


def export_domain_users(
    dc_ip: str,
    username: str,
    password: str,
    excluded_users: set[str],
) -> tuple[int, int]:
    """
    Export and filter domain user accounts.

    Domain users are exported from Active Directory using
    NetExec and written to 'domain-users.txt'. Testing
    accounts specified in 'excluded_users' are removed
    from the exported dataset and the resulting list is
    written to 'domain-users-filtered.txt'.

    Args:
        dc_ip: Domain Controller IP address.
        username: LDAP username.
        password: LDAP password.
        excluded_users: User accounts to exclude from
            the filtered dataset.

    Returns:
        A tuple containing:
        - Total exported users.
        - Total users after filtering.

    Raises:
        RuntimeError: If the user export fails.
    """

    artefacts_dir = get_artefacts_dir()
    with tempfile.TemporaryDirectory(dir=artefacts_dir, prefix=".users-") as directory:
        staged_users = Path(directory) / "domain-users.txt"
        staged_filtered = Path(directory) / "domain-users-filtered.txt"
        result = subprocess.run(
            [
                "nxc", "ldap", dc_ip,
                "-u", username,
                "-p", password,
                "--users-export", staged_users,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            detail = result.stderr.replace(password, "[REDACTED]").strip() if password else result.stderr.strip()
            raise RuntimeError(
                f"Failed to export domain users (exit code {result.returncode})"
                + (f": {detail}" if detail else ".")
            )
        if not staged_users.is_file():
            raise RuntimeError("Failed to export domain users: NetExec produced no export file.")

        users = [
            line.strip()
            for line in staged_users.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        user_count = len(users)
        filtered_users = [user for user in users if user.lower() not in excluded_users]
        staged_filtered.write_text("\n".join(filtered_users) + "\n", encoding="utf-8")
        staged_users.replace(artefacts_dir / "domain-users.txt")
        staged_filtered.replace(artefacts_dir / "domain-users-filtered.txt")

    return user_count, len(filtered_users)


def enumerate_domain_controllers(
    dc_ip: str,
    username: str,
    password: str,
) -> list[tuple[str, str]]:
    """
    Enumerate all Domain Controllers in the domain.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            LDAP username.

        password:
            LDAP password.

    Returns:
        List of Domain Controllers as (hostname, ip_address) tuples.

    Raises:
        RuntimeError:
            If Domain Controllers cannot be identified.
    """
    result = subprocess.run(
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "--dc-list",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError("Failed to enumerate Domain Controllers.")

    dcs = []

    dc_regex = re.compile(r"([A-Za-z0-9.-]+\.[A-Za-z0-9.-]+)\s*=\s*([0-9.]+)")

    for line in result.stdout.splitlines():

        match = dc_regex.search(line)

        if not match:
            continue

        hostname = match.group(1).upper()
        ip = match.group(2)

        dcs.append((hostname, ip))

    dcs = sorted(set(dcs))

    if not dcs:
        raise RuntimeError("No Domain Controllers were identified.")

    return dcs


def export_domain_computers(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
) -> int:
    """
    Export domain computer accounts.

    Args:
        domain: Active Directory domain name.
        dc_ip: Domain Controller IP address.
        username: LDAP username.
        password: LDAP password.

    Returns:
        Number of exported computer accounts.

    Raises:
        RuntimeError: If the export fails.
    """

    result = subprocess.run(
        ["nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
            "--computers",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        detail = result.stderr.replace(password, "[REDACTED]").strip() if password else result.stderr.strip()
        raise RuntimeError(
            f"Failed to export domain computers (exit code {result.returncode})"
            + (f": {detail}" if detail else ".")
        )

    computers = []

    computer_regex = re.compile(r"\b([A-Za-z0-9\-]+)\$")

    for line in result.stdout.splitlines():

        for match in computer_regex.findall(line):

            computers.append(f"{match.upper()}.{domain.upper()}")

    computers = sorted(set(computers))
    if not computers and not re.search(
        r"Total records returned:\s*0\b", result.stdout, re.IGNORECASE
    ):
        raise RuntimeError(
            "Failed to export domain computers: NetExec did not confirm an empty result."
        )

    artefacts_dir = get_artefacts_dir()
    with tempfile.TemporaryDirectory(dir=artefacts_dir, prefix=".computers-") as directory:
        staged_computers = Path(directory) / "domain-computers.txt"
        staged_computers.write_text(
            "\n".join(computers) + ("\n" if computers else ""),
            encoding="utf-8",
        )
        staged_computers.replace(artefacts_dir / "domain-computers.txt")

    return len(computers)


def print_summary(
    session_data: dict,
) -> None:
    """
    Print an enumeration summary.
    """

    print_section("Summary")

    table = Table(show_header=False)

    table.add_column("Item", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Domain", session_data["domain"])
    table.add_row("Domain Controllers", str(session_data["dc_count"]))
    table.add_row(
            "Standard User Authenticated (LDAP)",
            "Yes" if session_data["standard_user_validated"] else "No"
    )
    table.add_row(
        "Privileged Account (LDAP)",
        "Yes" if session_data["da_validated"] else "No"
    )
    table.add_row(
        "Domain Users", 
        str(session_data["domain_users_filtered_count"])
    )
    table.add_row(
        "Computer Accounts",
        str(session_data["domain_computers_count"])
    )
    table.add_row(
        "RustHound", 
        ("Completed" if session_data["rusthound_collected"] else "Skipped")
    )

    table.add_row(
        "NTDS Dump",
        (
            "Completed" if session_data["ntds_dumped"]
            else "Failed" if session_data.get("ntds_attempted")
            else "Skipped"
        ),
    )

    console.print(table)

#-------------------------------------------------------------------------------
# Main function
#-------------------------------------------------------------------------------
def run_enumeration() -> None:
    """
    Bootstrap an Active Directory assessment.

    This includes domain discovery, Domain Controller enumeration, credential 
    validation, domain data collection, and BloodHound collection.
    """

    #---------------------------------------------------------------------------
    # DOMAIN ENUMERATION
    #---------------------------------------------------------------------------
    
    try:

        #-----------------------------------------------------------------------
        # ASSESSMENT CONFIGURATION
        #-----------------------------------------------------------------------
        
        print_section("Assessment Configuration")

        dc_ip = typer.prompt("Domain Controller IP Address")
        console.print()

        # Initialise variables
        std_user = ""
        std_pass = ""

        da_user = ""
        da_pass = ""

        std_validated = False
        da_validated = False

        # Validate Standard User
        validate_std = typer.confirm(
            "Validate Standard User account?",
            default=True,
        )

        if validate_std:

            std_user = typer.prompt("Standard User Username")
            std_pass = typer.prompt("Standard User Password", hide_input=True)

        console.print()

        # Validate Domain Admin
        validate_da = typer.confirm(
            "Validate Domain Admin account?",
            default=True,
        )

        if validate_da:
    
            da_user = typer.prompt("Domain Admin Username")
            da_pass = typer.prompt("Domain Admin Password", hide_input=True)

        console.print()

        collect = typer.confirm("Run RustHound collection?", default=True)
        console.print()

        dump_ntds = False

        if validate_da:

            dump_ntds = typer.confirm("Dump NTDS hashes?", default=True)
            console.print()

        generate_scp_retrieval = typer.confirm(
            "Generate SCP retrieval command?",
            default=False,
        )
        
        #-----------------------------------------------------------------------
        # DOMAIN ENUMERATION
        #-----------------------------------------------------------------------
        print_section("Domain")

        hostname, domain = identify_domain_controller(dc_ip)

        dc_hostname = f"{hostname}.{domain}"
        dc_hostnames = [dc_hostname]
        dc_ips = [dc_ip]

        print_success(f"Identified Domain Controller: {dc_hostname}")
        print_success(f"Identified Domain: {domain}")

        #-----------------------------------------------------------------------
        # NXC CONFIGURATION (AUDIT MODE)
        #-----------------------------------------------------------------------
        
        print_section("NXC Configuration")

        configure_nxc()

        #-----------------------------------------------------------------------
        # DOMAIN ACCOUNTS VALIDATION
        #-----------------------------------------------------------------------
        
        print_section("Credential Validation")

        if not dc_ips:
            raise RuntimeError("No domain controller IPs could be resolved.")

        dc_ip = dc_ips[0]

        # Standard user
        if validate_std:

            valid, pwned = validate_credentials(dc_ip, std_user, std_pass)

            if not valid:
                print_error("Standard user LDAP authentication failed.")
                return

            if pwned:
                print_error("Standard user is marked privileged by NetExec LDAP.")
                return

            std_validated = True
            print_success("Standard user authenticated via LDAP (not marked privileged by NetExec).")

        # Domain Admin
        if validate_da:
            try:
                valid, pwned = validate_credentials(dc_ip, da_user, da_pass)
            except RuntimeError as exc:
                print_error(str(exc))
            else:
                if not valid:
                    print_error("Domain Admin LDAP authentication failed.")
                elif not pwned:
                    print_error(
                        "Account authenticated via LDAP but was not marked privileged by NetExec."
                    )
                else:
                    da_validated = True
                    print_success(
                        "Account authenticated via LDAP and marked privileged by NetExec."
                    )

            if not da_validated:
                if not std_validated:
                    return
                print_warning("Continuing enumeration using the validated standard user.")
                if dump_ntds:
                    print_warning("NTDS dump skipped because privileged access was not confirmed.")
                    dump_ntds = False

        if not validate_std and not validate_da:
            raise RuntimeError(
                "At least one authenticated account must be provided."
            )

        #-----------------------------------------------------------------------
        # DOMAIN CONTROLLER ENUMERATION
        #-----------------------------------------------------------------------

        print_section("Domain Controllers")

        # Use whichever account was validated
        ldap_user = ""
        ldap_pass = ""

        if std_validated:
            ldap_user = std_user
            ldap_pass = std_pass

        elif da_validated:
            ldap_user = da_user
            ldap_pass = da_pass

        domain_controllers = enumerate_domain_controllers(
            dc_ip,
            ldap_user,
            ldap_pass,
        )

        dc_hostnames = [
            hostname
            for hostname, _
            in domain_controllers
        ]

        dc_ips = [
            ip
            for _, ip
            in domain_controllers
        ]

        # Write results into disk
        write_results(domain, dc_hostnames, dc_ips,)

        print_success(
            f"Identified {len(domain_controllers)} Domain Controller(s)."
        )
        console.print()

        table = Table()

        table.add_column("Hostname", style="green")
        table.add_column("IP Address", style="cyan")

        for hostname, ip in domain_controllers:
            table.add_row(hostname, ip)

        console.print(table)

        #-----------------------------------------------------------------------
        # SESSION METADATA
        #-----------------------------------------------------------------------
        session_data = {
            "domain": domain,

            "dc_ip": dc_ip,
            "dc_hostname": dc_hostnames[0],
            "dc_ips": dc_ips,
            "dc_hostnames": dc_hostnames,
            "dc_count": len(dc_hostnames),

            "standard_user": std_user,
            "standard_user_validated": std_validated,

            "domain_admin": da_user,
            "da_validated": da_validated,

            "domain_users_exported": False,
            "domain_users_count": 0,
            "domain_users_filtered_count": 0,
            "excluded_users": sorted(
                account.lower() for account in [std_user, da_user] if account
            ),

            "domain_computers_exported": False,
            "domain_computers_count": 0,

            "rusthound_collected": False,

            "ntds_dumped": False,
            "ntds_attempted": False,

        }

        session_data["generate_scp_retrieval"] = (generate_scp_retrieval)

        save_session(session_data)

        #-----------------------------------------------------------------------
        # DOMAIN DATA COLLECTION
        #-----------------------------------------------------------------------
        
        print_section("Domain Data Collection")

        # Filter testing accounts
        excluded_users = {
            account.lower()
            for account in [std_user, da_user]
            if account
        }

        with progress("[cyan]Exporting domain users..."):
            user_count, filtered_count = export_domain_users(
                dc_ip,
                ldap_user,
                ldap_pass,
                excluded_users,
            )

        session_data["domain_users_exported"] = True
        session_data["domain_users_count"] = user_count
        session_data["domain_users_filtered_count"] = filtered_count
        session_data["excluded_users"] = sorted(excluded_users)
        save_session(session_data)

        # Print filtered accounts to stdout
        excluded_count = (user_count - filtered_count)
        print_success(f"Exported {filtered_count}/{user_count} domain users.")
        print_info(
            f"Filtered {excluded_count} testing account(s): "
            + ", ".join(sorted(excluded_users))
        )

        with progress("[cyan]Exporting computer accounts..."):
            computer_count = export_domain_computers(
                domain, 
                dc_ip, 
                ldap_user, 
                ldap_pass,
            )

        session_data["domain_computers_exported"] = True
        session_data["domain_computers_count"] = computer_count
        print_success(f"Exported {computer_count} computer accounts.")

        session_data["excluded_users"] = sorted(excluded_users)
        session_data["domain_users_filtered_count"] = filtered_count

        save_session(session_data)

        #-----------------------------------------------------------------------
        # BLOODHOUND DATA COLLECTION
        #-----------------------------------------------------------------------

        retrieval_files: list[Path] = []
        if collect:

            print_section("BloodHound Collection")

            output_dir = get_artefacts_dir()
            before = _artefact_snapshot(output_dir, "*.zip") if generate_scp_retrieval else {}
            with console.status("[cyan]Collecting BloodHound data..."):
                success = run_rusthound( domain, dc_ip, ldap_user, ldap_pass)

            if success:
                session_data["rusthound_collected"] = True
                if generate_scp_retrieval:
                    collected = _new_artefacts(output_dir, "*.zip", before)
                    if not collected:
                        print_warning("No new or updated BloodHound ZIP was found for retrieval.")
                    retrieval_files.extend(collected)
                save_session(session_data)

        #-----------------------------------------------------------------------
        # NTDS DUMP
        #-----------------------------------------------------------------------
        
        if dump_ntds:

            print_section("NTDS Dump")
            
            if not session_data["da_validated"]:
                print_error("A validated Domain Admin account is required.")

            else:
                output_dir = get_artefacts_dir()
                session_data["ntds_attempted"] = True
                dumped = _dump_ntds(
                    domain, da_user, da_pass,
                    [dc_ip, *dc_ips], output_dir,
                )
                if dumped:
                    output_file, dump_dc = dumped
                    session_data["ntds_dumped"] = True
                    session_data["ntds_dc"] = dump_dc
                    if generate_scp_retrieval:
                        retrieval_files.append(output_file)
                    print_success(f"NTDS dump completed using {dump_dc}.")
                else:
                    print_error("NTDS dump failed; no complete dump was collected.")
                save_session(session_data)

        #-----------------------------------------------------------------------
        # SCP COMMAND & SUMMARY TABLE
        #-----------------------------------------------------------------------
        
        if generate_scp_retrieval:
            generate_scp_command(retrieval_files)
        
        print_summary(session_data)


    except Exception as exc:
        print_error(str(exc))