"""
UV installer implementation.

This installer is responsible for installing tools through
the uv tool management system.
"""

import subprocess

from rich.console import Console
from pathlib import Path
from shutil import which

from ad_kit.core.console import print_info, print_success
from ad_kit.models import Tool
from ad_kit.installers.base import Installer
from ad_kit.core.exceptions import InstallationError

console = Console()


class UVInstaller(Installer):
    """
    Install tools using uv.
    """

    def _extract_failure_reason(self, stderr: str) -> str:
        """
        Extract a concise failure reason from uv output.

        Args:
            stderr: Raw stderr output from uv.

        Returns:
            Human-readable failure reason.
        """

        if "netifaces" in stderr:
            return (
                "Dependency 'netifaces==0.11.0' failed to build "
                "(likely incompatible with Python 3.13)."
            )

        lines = [
            line.strip()
            for line in stderr.splitlines()
            if line.strip()
        ]

        if lines:
            return lines[-1]

        return "Unknown installation error."


    def install(self, tool: Tool) -> None:
        """
        Install a UV-managed tool.

        Args:
            tool: Tool definition.
        """

        existing = (
            which(tool.check_command)
            if tool.check_command
            else None
        )

        uv_bin = str(Path.home() / ".local" / "bin")

        if existing and not existing.startswith(uv_bin):
            raise InstallationError(
                tool.name,
                (
                    f"Conflicting installation detected at '{existing}'. "
                    "Remove the existing installation and rerun AD-Kit."
                ),
            )

        print_info(f"Installing {tool.name}...")

        result = subprocess.run(
            [
                "uv",
                "tool",
                "install",
                "--reinstall",
                "--force",
                tool.source,
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            reason = self._extract_failure_reason(result.stderr)
            raise InstallationError(tool.name, reason)

        print_success(f"Successfully installed {tool.name}")

        if tool.check_command:

            installed = which(tool.check_command)

            if installed:
                print_info(f"Installed path: {installed}")