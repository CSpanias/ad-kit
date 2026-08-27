"""
Initial engagement enumeration functionality.
"""

import json
import re
import socket
import subprocess
import typer

from pathlib import Path
from rich.table import Table

from ad_kit.core.console import print_error, print_info, print_success, print_section, console
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
        "Unable to determine domain automatically. Enter domain"
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

    Path("domain.txt").write_text(f"{domain}\n", encoding="utf-8")

    dc_hostnames = sorted(dc_hostnames)
    Path("dc-hostnames.txt").write_text(
        "\n".join(dc_hostnames) + "\n",
        encoding="utf-8",
    )

    dc_ips = sorted(dc_ips)
    Path("dc-ips.txt").write_text("\n".join(dc_ips) + "\n", encoding="utf-8")


def validate_credentials(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[bool, bool]:
    """
    Validate credentials using NetExec.

    Returns:
        (
            authentication_successful,
            privileged_access,
        )
    """
    result = subprocess.run(
        [
            "nxc", "smb", dc_ip,
            "-u", username,
            "-p", password,
        ],
        capture_output=True,
        text=True,
    )

    output = result.stdout

    is_valid = "[+]" in output
    is_pwned = "Pwn3d!" in output

    return (is_valid, is_pwned)


def run_enumeration() -> None:
    """
    Perform initial domain enumeration.
    """

    #-----------------------------------------------------------------------
    # Domain enumeration
    #-----------------------------------------------------------------------
    print_section("Domain")

    try:
        domain = discover_domain()

        print_success(f"Domain: {domain}")

        #-----------------------------------------------------------------------
        # Domain Controller(s) enumeration
        #-----------------------------------------------------------------------
        print_section("Domain controllers")
        print("")

        dc_hostnames = enumerate_domain_controllers(domain)
        dc_ips = resolve_domain_controllers(dc_hostnames)

        table = Table(title="")

        table.add_column("Hostname", style="green")
        table.add_column("IP Address", style="cyan")

        for hostname, ip in zip(dc_hostnames, dc_ips):
            table.add_row(hostname, ip)

        console.print(table)

        #-----------------------------------------------------------------------
        # Output files
        #-----------------------------------------------------------------------
        print_section("Artefact Generation")

        write_results(domain, dc_hostnames, dc_ips)
        print("")
        print_success("Results written successfully.")

        #-----------------------------------------------------------------------
        # Domain account(s) validation
        #-----------------------------------------------------------------------
        print_section("Credential Validation")

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
            "standard_user": std_user,
            "domain_admin": da_user,
            "da_validated": True,
            "rusthound_collected": False,
        }

        Path(".ad-kit-session.json").write_text(
            json.dumps(session_data,indent=4,),
            encoding="utf-8",
        )

        #-----------------------------------------------------------------------
        # Domain data collection
        #-----------------------------------------------------------------------
        print_section("BloodHound Collection")
        
        collect = typer.confirm("Run RustHound collection?", default=True)

        if collect:
            success = run_rusthound(domain, dc_ip, std_user, std_pass)

            if success:
                session_data["rusthound_collected"] = True

                Path(".ad-kit-session.json").write_text(
                    json.dumps(session_data, indent=4),
                    encoding="utf-8",
                )

    except Exception as exc:
        print_error(str(exc))