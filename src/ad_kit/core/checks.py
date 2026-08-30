"""
Assessment check helpers.
"""

import subprocess

from pathlib import Path

from ad_kit.core.util import get_artefacts_dir, progress

#-------------------------------------------------------------------------------
# Constants
#-------------------------------------------------------------------------------

PASSWORD_POLICY_BASELINE = {
    "minimum_length": 12,
    "password_history": 12,
    "minimum_age_days": 1,
    "lockout_threshold": 5,
    "lockout_duration_minutes": 30,
    "observation_window_minutes": 15,
}

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------

def get_evidence_dir() -> Path:
    """
    Return the AD-Kit evidence directory.
    """

    evidence_dir = (get_artefacts_dir() / "evidence")
    evidence_dir.mkdir(exist_ok=True)

    return evidence_dir


def load_dc_ips() -> list:
    """
    Load enumerated Domain Controller IP addresses.
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
    """

    computers_file = (get_artefacts_dir() / "domain-computers.txt")

    return [
        line.strip()
        for line in computers_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_dc_hostnames() -> list:
    """
    Load Domain Controller hostnames.
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

def run_check(
    name: str,
    command: list[str],
) -> str:
    """
    Execute a check and save the output.

    Args:
        name: Evidence filename prefix.
        command: Command to execute.

    Returns:
        Command stdout.

    Raises:
        RuntimeError: If the command fails.
    """

    with progress(f"Running {' '.join(command)}"):
        result = subprocess.run(command, capture_output=True, text=True)
        
    evidence_file = (get_evidence_dir() / f"{name}.txt")
    evidence = (f"$ {' '.join(command)}\n\n {result.stdout}")
    evidence_file.write_text(evidence, encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(f"Check failed: {name}")

    return result.stdout