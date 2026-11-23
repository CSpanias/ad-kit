"""
GitHub release installer.
"""

import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path
from shutil import which

import requests

from ad_kit.config import INSTALL_DIR
from ad_kit.core.console import print_info, print_success, print_warning
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
        if not tool.asset_pattern:
            raise InstallationError(tool.name, "No release asset pattern is configured.")
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

        if not tool.binary_name:
            raise InstallationError(tool.name, "No binary name is configured.")
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        destination = INSTALL_DIR / tool.binary_name
        with tempfile.NamedTemporaryFile(dir=INSTALL_DIR, delete=False) as temp:
            temp_path = Path(temp.name)
        try:
            shutil.copy2(binary_path, temp_path)
            temp_path.chmod(temp_path.stat().st_mode | stat.S_IEXEC)
            os.replace(temp_path, destination)
        finally:
            temp_path.unlink(missing_ok=True)

        print_info(f"Installing binary to: {destination}")


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

    def install(self, tool: Tool, force: bool = False) -> None:
        """
        Install a GitHub release binary.
        """

        existing = which(tool.check_command) if tool.check_command else None
        if existing and not force:
            print_info(f"{tool.name} is already installed at {existing}. Use --force to reinstall.")
            return

        if not tool.repo or not tool.binary_name:
            raise InstallationError(
                tool.name, "Release repository or binary name is not configured."
            )

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
            if tool.check_command:
                active = which(tool.check_command)
                destination = INSTALL_DIR / tool.binary_name
                if active and Path(active).resolve() != destination.resolve():
                    print_warning(
                        f"{active} takes precedence on PATH; {tool.name} may still run "
                        f"the existing version instead of {destination}."
                    )
                elif not active:
                    print_warning(f"{destination} is not on PATH.")
                if force and existing:
                    print_info(
                        "If your shell still runs the old version, refresh its command cache "
                        "(bash: hash -r; zsh: rehash)."
                    )

        except Exception as exc:
            raise InstallationError(tool.name, str(exc))