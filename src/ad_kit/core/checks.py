"""
Assessment check helpers.
"""

import subprocess

from pathlib import Path

from ad_kit.core.util import get_artefacts_dir


def get_evidence_dir() -> Path:
    """
    Return the AD-Kit evidence directory.
    """

    evidence_dir = (get_artefacts_dir() / "evidence")
    evidence_dir.mkdir(exist_ok=True)

    return evidence_dir


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

    result = subprocess.run(command, capture_output=True, text=True)
    evidence_file = (get_evidence_dir() / f"{name}.txt")
    evidence = (f"$ {' '.join(command)}\n\n {result.stdout}")
    evidence_file.write_text(evidence, encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(f"Check failed: {name}")

    return result.stdout