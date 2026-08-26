"""
UV installer implementation.

This installer is responsible for installing tools through
the uv tool management system.
"""

import subprocess

from rich.console import Console
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

        # Check if the tool is already installed
        if tool.check_command and which(tool.check_command):
            print_info(f"{tool.name} is already installed.")
            return

        print_info(f"Installing {tool.name}...")

        result = subprocess.run(
            [
                "uv",
                "tool",
                "install",
                tool.source,
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            reason = self._extract_failure_reason(result.stderr)
            raise InstallationError(tool.name, reason)

        print_success(f"Successfully installed {tool.name}")