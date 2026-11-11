"""
Authentication coercion assessment checks.
"""

from ad_kit.core.checks import run_check, load_dc_hostnames
from ad_kit.core.util import get_artefacts_dir


def coercion_check(
    dc_ip: str,
    username: str,
    password: str,
) -> dict:
    """
    Identify systems exposing authentication coercion techniques and Domain 
    Controllers with the Print Spooler service enabled.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            LDAP username.

        password:
            LDAP password.

    Returns:
        Dictionary containing identified coercion techniques and Domain 
        Controllers running the Print Spooler service.
    """

    dc_hostnames = {
        hostname.split(".")[0].upper()
        for hostname in load_dc_hostnames()
    }

    spooler_output = run_check(
        "coercion-spooler",
        [
            "nxc",
            "smb",
            str(
                get_artefacts_dir()
                / "domain-computers.txt"
            ),
            "-u",
            username,
            "-p",
            password,
            "-M",
            "spooler",
        ],
    )

    coercion_output = run_check(
        "coercion-plus",
        [
            "nxc",
            "smb",
            str(
                get_artefacts_dir()
                / "domain-computers.txt"
            ),
            "-u",
            username,
            "-p",
            password,
            "-M",
            "coerce_plus",
        ],
    )

    spooler_dcs = set()

    coercion_hosts = {}

    #---------------------------------------------------------------------------
    # SPOOLER
    #---------------------------------------------------------------------------

    for line in spooler_output.splitlines():

        if "Spooler service enabled" not in line:
            continue

        parts = line.split()

        if len(parts) < 4:
            continue

        hostname = parts[3].upper()

        if hostname in dc_hostnames:

            spooler_dcs.add(hostname)

    #---------------------------------------------------------------------------
    # COERCION
    #---------------------------------------------------------------------------

    for line in coercion_output.splitlines():

        if "VULNERABLE," not in line:
            continue

        parts = line.split()

        if len(parts) < 4:
            continue

        hostname = parts[3].upper()

        technique = line.split("VULNERABLE,", 1)[1].strip()

        coercion_hosts.setdefault(hostname, set()).add(technique)

    return {
        "spooler_dcs": sorted(spooler_dcs),
        "coercion_hosts": {
            host: sorted(techniques)
            for host, techniques
            in sorted(coercion_hosts.items())
        },
    }