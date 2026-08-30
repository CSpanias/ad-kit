"""
Initial engagement enumeration functionality.
"""

import re
import socket
import subprocess
import typer

from pathlib import Path
from rich.table import Table

from ad_kit.core.checks import run_check
from ad_kit.core.console import (
    print_error, 
    print_info, 
    print_success, 
    print_section, 
    console
)
from ad_kit.core.util import (
    get_artefacts_dir, 
    save_session, 
    generate_scp_command,
    progress
)
from ad_kit.commands.rusthound import run_rusthound


# TODO:
# Validate domain discovery logic on a real engagement.
# Current implementation relies on resolvectl and
# /etc/resolv.conf and may need additional discovery
# methods or fallback prompting.

def discover_domain() -> str:
    """
    Discover the Active Directory domain.

    Returns:
        Domain name.

    Raises:
        RuntimeError: If the domain cannot be determined.
    """

    try:
        result = subprocess.run(
            ["resolvectl", "domain"],
            capture_output=True,
            text=True,
            check=False,
        )

        domains = re.findall(
            r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            result.stdout,
        )

        if domains:
            return domains[0]

    except FileNotFoundError:
        pass

    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("search "):
                    candidate = line.split()[1].strip()

                    if "." in candidate and candidate != ".":
                        return candidate
                    
    except OSError:
        pass

    domain = typer.prompt(
        "Unable to determine domain automatically.\n"
        "Enter domain"
    )

    return domain


def enumerate_domain_controllers(
    domain: str,
) -> list[str]:
    """
    Enumerate domain controllers via DNS.

    Args:
        domain: AD domain name.

    Returns:
        List of DC hostnames.

    Raises:
        RuntimeError: If enumeration fails.
    """

    print_info("Querying Active Directory DNS...")
    print("")

    result = subprocess.run(
        [
            "nslookup",
            "-type=SRV",
            f"_ldap._tcp.dc._msdcs.{domain}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if (
        result.returncode != 0
        or "REFUSED" in result.stdout
        or "can't find" in result.stdout
    ):
        raise RuntimeError("Failed to query DNS SRV records.")

    dc_hostnames: set[str] = set()

    for line in result.stdout.splitlines():
        if "service =" in line:
            hostname = line.split()[-1].rstrip(".")
            dc_hostnames.add(hostname)

    if not dc_hostnames:
        raise RuntimeError("" \
        "No domain controllers were found in DNS. Ensure your DNS server is "
        "pointing at a domain controller."
    )

    return sorted(dc_hostnames)


def resolve_domain_controllers(
    dc_hostnames: list[str],
) -> list[str]:
    """
    Resolve DC hostnames to IP addresses.

    Args:
        dc_hostnames: List of DC hostnames.

    Returns:
        List of IP addresses.
    """

    dc_ips: list[str] = []

    for hostname in dc_hostnames:
        try:
            ip = socket.gethostbyname(hostname)
            dc_ips.append(ip)

        except socket.gaierror:
            continue

    return dc_ips


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
) -> bool:
    """
    Validate LDAP credentials.
    """

    output = run_check(
        "credential-validation",
        ["nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
        ],
    )

    for line in output.splitlines():

        lower = line.lower()

        if f"\\{username.lower()}:" not in lower:
            continue

        if "[+]" in line:
            return True

        if "[-]" in line:
            return False

    return False


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

    users_file = (get_artefacts_dir() / "domain-users.txt")

    subprocess.run(
        [
            "nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
            "--users-export", users_file,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    if not users_file.exists():
        raise RuntimeError("Failed to export domain users.")

    users = [
        line.strip()
        for line in users_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    user_count = len(users)

    filtered_users = [
        user
        for user in users
        if user.lower() not in excluded_users
    ]

    (
        get_artefacts_dir()
        / "domain-users-filtered.txt"
    ).write_text(
        "\n".join(filtered_users) + "\n",
        encoding="utf-8",
    )

    return user_count, len(filtered_users)


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

    computers = []

    for line in result.stdout.splitlines():

        candidate = line.strip().split()[-1]

        if candidate.endswith("$"):

            fqdn = (candidate.rstrip("$").upper() + f".{domain.upper()}")
            computers.append(fqdn)

    computers = sorted(set(computers))

    (
        get_artefacts_dir()
        / "domain-computers.txt"
    ).write_text(
        "\n".join(computers) + "\n",
        encoding="utf-8",
    )

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
            "Standard User Validated",
            "Yes" if session_data["standard_user_validated"] else "No"
    )
    table.add_row(
        "DA Validated",
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
    # Domain enumeration
    #---------------------------------------------------------------------------
    print_section("Domain")

    try:
        domain = discover_domain()
        print_success(f"Domain: {domain}")

        #-----------------------------------------------------------------------
        # Domain Controller(s) enumeration
        #-----------------------------------------------------------------------
        print_section("Domain controllers")

        dc_hostnames = enumerate_domain_controllers(domain)
        dc_ips = resolve_domain_controllers(dc_hostnames)

        table = Table()

        table.add_column("Hostname", style="green")
        table.add_column("IP Address", style="cyan")

        for hostname, ip in zip(dc_hostnames, dc_ips):
            table.add_row(hostname, ip)

        console.print(table)

        # Write results into disk
        write_results(domain, dc_hostnames, dc_ips)

        #-----------------------------------------------------------------------
        # NetExec Configuration (audit mode)
        #-----------------------------------------------------------------------
        print_section("NXC Configuration")
        configure_nxc()
        print("")

        #-----------------------------------------------------------------------
        # Domain account(s) validation
        #-----------------------------------------------------------------------
        print_section("Credential Validation")

        if not dc_ips:
            raise RuntimeError("No domain controller IPs could be resolved.")

        dc_ip = dc_ips[0]

        # Standard user
        print_info("Enter standard user credentials.")
        std_user = typer.prompt("Username")
        std_pass = typer.prompt("Password", hide_input=True)
        print("")

        valid, pwned = validate_credentials(dc_ip, std_user, std_pass)

        if not valid:
            print_error("Standard user validation failed.")
            return

        if pwned:
            print_error("Standard user appears privileged.")
        else:
            print_success("Standard user validated.")

        print("")

        # Domain Admin
        print_info("Enter Domain Admin credentials.")

        da_user = typer.prompt("Username")
        da_pass = typer.prompt("Password", hide_input=True)

        valid, pwned = validate_credentials(dc_ip, da_user, da_pass)

        if not valid:
            print_error("Domain Admin validation failed.")
            return

        if not pwned:
            print_error(
                "Account authenticated but does not appear to be privileged."
            )
            return

        print_success("Domain Admin validated.")

        #-----------------------------------------------------------------------
        # Session metadata
        #-----------------------------------------------------------------------
        session_data = {
            "domain": domain,
            "dc_ip": dc_ip,
            "dc_hostname": dc_hostnames[0],
            "dc_count": len(dc_hostnames),

            "standard_user": std_user,
            "standard_user_validated": True,

            "domain_admin": da_user,
            "da_validated": True,

            "domain_users_exported": False,
            "domain_users_count": 0,
            "domain_users_filtered_count": 0,
            "domain_users_exported": False,


            "domain_computers_exported": False,
            "domain_computers_count": 0,

            "rusthound_collected": False,
            "ntds_dumped": False,
            "jumpbox_host": "",
            "jumpbox_user": "",
            "ssh_key": "",
        }

        save_session(session_data)

        #-----------------------------------------------------------------------
        # Domain data collection
        #-----------------------------------------------------------------------
        print_section("Domain Data Collection")

        # Filter testing accounts
        excluded_users = {std_user.lower(), da_user.lower()}

        with progress("[cyan]Exporting domain users..."):
            user_count, filtered_count = export_domain_users(
                dc_ip,
                std_user,
                std_pass,
                excluded_users,
            )

        print_info(f"Filtered accounts:\n{excluded_users}")
        print("")
        session_data["domain_users_exported"] = True
        session_data["domain_users_count"] = user_count

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
                std_user, 
                std_pass
            )

        session_data["domain_computers_exported"] = True
        session_data["domain_computers_count"] = computer_count
        print_success(f"Exported {computer_count} computer accounts.")

        session_data["excluded_users"] = sorted(excluded_users)
        session_data["domain_users_filtered_count"] = filtered_count

        save_session(session_data)

        #-----------------------------------------------------------------------
        # BloodHound collection
        #-----------------------------------------------------------------------
        
        print_section("BloodHound Collection")
        
        collect = typer.confirm("Run RustHound collection?", default=True)

        if collect:
            with console.status("[cyan]Collecting BloodHound data..."):
                success = run_rusthound( domain, dc_ip, std_user, std_pass)

            if success:
                session_data["rusthound_collected"] = True
                save_session(session_data)

        # Create SCP command
        print("")
        if typer.confirm("Generate SCP retrieval command?", default=True):
            generate_scp_command(session_data)

        #-----------------------------------------------------------------------
        # Summary table
        #-----------------------------------------------------------------------
        print_summary(session_data)


    except Exception as exc:
        print_error(str(exc))