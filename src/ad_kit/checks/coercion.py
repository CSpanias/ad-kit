"""
Authentication coercion assessment checks.
"""

from ad_kit.core.checks import run_check, load_dc_hostnames
from ad_kit.core.util import get_artefacts_dir


def extract_hostname(
    line: str,
) -> str | None:
    """
    Extract the target hostname from NetExec module output.

    Args:
        line:
            NetExec output line.

    Returns:
        Uppercase hostname if successfully parsed, otherwise None.
    """

    parts = line.split()

    if len(parts) < 4:
        return None

    return parts[3].upper()


def coercion_check(
    username: str,
    password: str,
) -> dict:
    """
    Identify systems exposing authentication coercion techniques and Domain 
    Controllers (DCs) with the Print Spooler service enabled.

    Args:
        username:
            LDAP username.

        password:
            LDAP password.

    Returns:
        Dictionary containing identified coercion techniques and DCs running 
        the Print Spooler service.
    """

    targets = str(
        get_artefacts_dir()
        / "dc-hostnames.txt"
    )

    dc_hostnames = {
        hostname.split(".")[0].upper()
        for hostname in load_dc_hostnames()
    }

    spooler_output = run_check(
        "coercion-spooler",
        [
            "nxc", "smb", targets,
            "-u", username,
            "-p", password,
            "-M", "spooler",
        ],
    )

    coercion_output = run_check(
        "coercion-plus",
        [
            "nxc", "smb", targets,
            "-u", username,
            "-p", password,
            "-M", "coerce_plus",
        ],
    )

    webdav_output = run_check(
        "coercion-webdav",
        [
            "nxc", "smb", targets,
            "-u", username,
            "-p", password,
            "-M", "webdav",
        ],
    )

    spooler_dcs: set[str] = set()

    coercion_dcs: dict[str, set[str]] = {}

    #---------------------------------------------------------------------------
    # SPOOLER
    #---------------------------------------------------------------------------

    for line in spooler_output.splitlines():

        if "Spooler service enabled" not in line:
            continue

        hostname = extract_hostname(line)
        
        if hostname is None:
            continue

        if hostname in dc_hostnames:

            spooler_dcs.add(hostname)

    #---------------------------------------------------------------------------
    # WEBDAV
    #---------------------------------------------------------------------------

    for line in webdav_output.splitlines():

        if "WebClient Service enabled" not in line:
            continue

        hostname = extract_hostname(line)

        if hostname is None:
            continue

        coercion_dcs.setdefault(hostname, set()).add("WebDAV")

    #---------------------------------------------------------------------------
    # COERCION
    #---------------------------------------------------------------------------

    for line in coercion_output.splitlines():

        if "VULNERABLE," not in line:
            continue

        hostname = extract_hostname(line)
        
        if hostname is None:
            continue

        technique = line.split("VULNERABLE,", 1)[1].strip()

        coercion_dcs.setdefault(hostname, set()).add(technique)

    return {
        "spooler_dcs": sorted(spooler_dcs),
        "coercion_dcs": {
            host: sorted(techniques)
            for host, techniques
            in sorted(coercion_dcs.items())
        },
    }