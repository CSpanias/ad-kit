"""
Assessment check helpers.

This module provides shared functionality used by AD-Kit assessment checks, 
including evidence management, credential validation, command execution, and 
helper functions for loading enumerated Active Directory assets.
"""

import subprocess

from pathlib import Path

from ad_kit.core.util import get_artefacts_dir, progress

#-------------------------------------------------------------------------------
# CONSTANTS
#-------------------------------------------------------------------------------

PASSWORD_POLICY_BASELINE = {
    "minimum_length": 12,
    "password_history": 2,
    "minimum_age_days": 1,
    "lockout_threshold": 5,
    "lockout_duration_minutes": 30,
    "observation_window_minutes": 15,
}

#-------------------------------------------------------------------------------
# FUNCTIONS
#-------------------------------------------------------------------------------

def get_evidence_dir() -> Path:
    """
    Return the AD-Kit evidence directory.

    The evidence directory is used to store raw command output collected during 
    assessment checks. The directory is created automatically if it does not
    already exist.

    Returns:
        Path to the evidence directory.
    """

    evidence_dir = (get_artefacts_dir() / "evidence")
    evidence_dir.mkdir(exist_ok=True)

    return evidence_dir


def load_dc_ips() -> list:
    """
    Load enumerated Domain Controller IP addresses.

    Reads the Domain Controller IP address list generated during the 
    enumeration phase and returns the values as a list.

    Returns:
        List of Domain Controller IP addresses.
    """

    dc_ips_file = (get_artefacts_dir() / "dc-ips.txt")

    return [
        line.strip()
        for line in dc_ips_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_domain_computers() -> list:
    """
    Load enumerated domain computers.

    Reads the domain computer list generated during enumeration and returns the 
    values as a list.

    Returns:
        List of domain computer hostnames.
    """

    computers_file = (get_artefacts_dir() / "domain-computers.txt")

    return [
        line.strip()
        for line in computers_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_dc_hostnames() -> list:
    """
    Load enumerated Domain Controller hostnames.

    Reads the Domain Controller hostname list generated during enumeration and 
    returns the values as a list.

    Returns:
        List of Domain Controller hostnames.
    """

    dc_file = (get_artefacts_dir() / "dc-hostnames.txt")

    return [
        line.strip()
        for line in dc_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def duration_to_minutes(
    value: str,
) -> int | None:
    """
    Convert NetExec duration strings to minutes.

    This helper converts NetExec duration values such as '30 minutes', '2 hours 
    30 minutes', or '1 day 12 hours' into their equivalent number of minutes to 
    simplify password policy assessment logic.

    Args:
        value:
            NetExec duration string.

    Returns:
        Duration expressed in minutes, or None if the value cannot be 
        determined.
    """

    if value == "Unknown":
        return None

    minutes = 0

    tokens = value.lower().split()

    for i, token in enumerate(tokens):

        if token == "days":
            minutes += int(tokens[i - 1]) * 1440

        elif token == "hours":
            minutes += int(tokens[i - 1]) * 60

        elif token == "minutes":
            minutes += int(tokens[i - 1])

    return minutes


def validate_credentials(
    dc_ip: str,
    username: str,
    password: str,
) -> str:
    """
    Validate Active Directory credentials.

    Authentication is performed against the target Domain Controller using 
    NetExec LDAP authentication.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Account password.

    Returns:
        One of the following status values:

        - 'valid'
        - 'invalid'
        - 'locked'
        - 'unknown'
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
            return "valid"

        if "user_account_locked" in lower:
            return "locked"

        if "[-]" in line:
            return "invalid"

    return "unknown"


def run_check(
    name: str,
    command: list[str],
) -> str:
    """
    Execute an assessment check and preserve evidence.

    The supplied command is executed, its output is written to the assessment 
    evidence directory, and the command stdout is returned to the caller for
    parsing.

    Args:
        name:
            Evidence filename prefix.

        command:
            Command and arguments to execute.

    Returns:
        Command standard output.

    Raises:
        RuntimeError:
            If the command exits with a non-zero return code.
    """

    with progress(f"Running {' '.join(command)}"):
        result = subprocess.run(command, capture_output=True, text=True)
        
    evidence_file = (get_evidence_dir() / f"{name}.txt")
    evidence = (f"$ {' '.join(command)}\n\n {result.stdout}")
    evidence_file.write_text(evidence, encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(f"Check failed: {name}")

    return result.stdout