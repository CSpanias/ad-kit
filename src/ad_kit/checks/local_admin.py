"""
Local Administrator access assessment checks.
"""

from pathlib import Path

from ad_kit.core.checks import run_check, load_dc_hostnames
from ad_kit.core.finding import Finding


def local_admin_check(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
) -> dict:
    """
    Determine whether the supplied user has local administrator access on any 
    domain-joined hosts.

    Args:
        dc_ip:
            Domain Controller IP address.

        domain:
            Active Directory domain name.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        Dictionary containing identified hosts where local administrator access 
        was detected.
    """

    hosts_file = Path("ad-kit/domain-computers.txt")

    if not hosts_file.exists():

        output = run_check(
            "local-admin-computers",
            [
                "nxc",
                "ldap",
                dc_ip,
                "-u",
                username,
                "-p",
                password,
                "--computers",
            ],
        )

        fqdns = []

        for line in output.splitlines():

            parts = line.split()

            if len(parts) < 5:
                continue

            computer = parts[4]

            if not computer.endswith("$"):
                continue

            fqdns.append(f"{computer.rstrip('$')}.{domain}")

        hosts_file.write_text(
            "\n".join(sorted(set(fqdns))) + "\n",
            encoding="utf-8",
        )

    output = run_check(
        "local-admin-access",
        [
            "nxc",
            "smb",
            str(hosts_file),
            "-u",
            username,
            "-p",
            password,
        ],
    )

    dc_hostnames = {dc.lower() for dc in load_dc_hostnames()}

    workstation_access = set()
    dc_access = set()

    for line in output.splitlines():

        if "(Pwn3d!)" not in line:
            continue

        parts = line.split()

        if len(parts) < 4:
            continue

        hostname = parts[3].strip()

        if hostname.lower() in dc_hostnames:

            dc_access.add(hostname)

        else:

            workstation_access.add(hostname)

    return {
        "hosts": sorted(workstation_access),
        "domain_controllers": sorted(dc_access),
    }