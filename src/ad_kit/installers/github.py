"""
GitHub release installer.
"""

import requests
import shutil
import stat
import subprocess
import tarfile
import tempfile

from pathlib import Path
from shutil import which

from ad_kit.config import INSTALL_DIR
from ad_kit.core.console import print_info, print_success
from ad_kit.core.exceptions import InstallationError
from ad_kit.installers.base import Installer
from ad_kit.models import Tool


class GitHubReleaseInstaller(Installer):
    """
    Install tools distributed through GitHub Releases.
    """


    def _get_latest_release(self, repo: str) -> dict:
        """
        Retrieve the latest GitHub release.
        """
        response = requests.get(
            f"https://api.github.com/repos/{repo}/releases/latest",
            timeout=30,
        )

        response.raise_for_status()

        return response.json()


    def _find_asset(
        self,
        tool: Tool,
        assets: list[dict],
    ) -> dict:
        """
        Find a matching release asset.

        Args:
            tool: Tool definition.
            assets: GitHub release assets.

        Returns:
            Matching asset metadata.

        Raises:
            InstallationError: If no asset matches.
        """
        for asset in assets:
            if tool.asset_pattern in asset["name"]:
                return asset

        raise InstallationError(
            tool.name,
            f"No release asset matching '{tool.asset_pattern}' was found."
        )


    def _install_binary(
        self,
        tool: Tool,
        binary_path: Path,
    ) -> None:
        """
        Install a standalone binary.

        Args:
            tool: Tool definition.
            binary_path: Path to the downloaded binary.
        """

        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC)
        shutil.copy2(binary_path, INSTALL_DIR / tool.binary_name)

        print_info(f"Installing binary to: {INSTALL_DIR / tool.binary_name}")


    def _install_from_tarball(
        self,
        tool: Tool,
        archive_path: Path,
        extraction_dir: Path,
    ) -> None:
        """
        Install a tool distributed as a tar.gz archive.

        Args:
            tool: Tool definition.
            archive_path: Downloaded archive path.
            extraction_dir: Temporary extraction directory.
        """
        with tarfile.open(
            archive_path,
            "r:gz",
        ) as archive:
            archive.extractall(extraction_dir)

        binary = next(
            (
                file
                for file in extraction_dir.rglob("*")
                if file.is_file()
                and file.name == tool.binary_name
            ),
            None,
        )

        if binary is None:
            raise InstallationError(
                tool.name,
                "Could not locate extracted RustHound binary.",
            )

        self._install_binary(
            tool,
            binary,
        )

    def install(self, tool: Tool) -> None:
        """
        Install a GitHub release binary.
        """

        # Check if the tool is already installed
        if tool.check_command and which(tool.check_command):
            print_info(f"{tool.name} is already installed.")
            return

        print_info(f"Installing {tool.name}...")

        try:
            release = self._get_latest_release(tool.repo)
            asset = self._find_asset(tool, release["assets"])
            url = asset["browser_download_url"]
            asset_name = asset["name"]

            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                download_path = tmp_path / asset_name

                subprocess.run(
                    [
                        "wget",
                        "-q",
                        "-O",
                        str(download_path),
                        url,
                    ],
                    check=True,
                )

                if asset_name.endswith(".tar.gz"):
                    self._install_from_tarball(tool, download_path, tmp_path)
                else:
                    self._install_binary(tool, download_path)

            print_success(f"Successfully installed {tool.name}")

        except Exception as exc:
            raise InstallationError(tool.name, str(exc))