"""
Initial engagement enumeration functionality.
"""

import re
import socket
import subprocess
import typer

from pathlib import Path

from ad_kit.core.console import print_error, print_info, print_success
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


def run_enumeration() -> None:
    """
    Perform initial domain enumeration.
    """

    print_info("Discovering domain...")

    try:
        domain = discover_domain()

        print_success(f"Domain: {domain}")

        print_info("Enumerating domain controllers...")

        print("")
        dc_hostnames = enumerate_domain_controllers(domain)

        for hostname in dc_hostnames:
            print_success(hostname)

        print("")
        print_info("Resolving domain controllers...")

        dc_ips = resolve_domain_controllers(dc_hostnames)

        print_info(f"Detected {len(dc_hostnames)} DC(s).")
        print_info(f"Resolved {len(dc_ips)} DC IP(s).")

        for ip in dc_ips:
            print_success(ip)

        write_results(domain, dc_hostnames, dc_ips)
        print("")
        print_success("Results written successfully.")

        collect = typer.confirm("Run RustHound collection?", default=True)

        if collect:
            run_rusthound(domain, dc_ips[0])

    except Exception as exc:
        print_error(str(exc))