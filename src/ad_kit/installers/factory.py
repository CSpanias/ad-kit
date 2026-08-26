"""
Installer factory.

Responsible for returning the correct installer
implementation based on the configured installer type.
"""

from ad_kit.installers.github import GitHubReleaseInstaller
from ad_kit.installers.uv import UVInstaller


def get_installer(installer_type: str) -> UVInstaller:
    """
    Return an installer implementation.

    Args:
        installer_type: Installer type identifier.

    Returns:
        Installer implementation.

    Raises:
        NotImplementedError: If the installer type is unsupported.
    """
    match installer_type:
        case "uv":
            return UVInstaller()

        case "github_release":
            return GitHubReleaseInstaller()

        case _:
            raise NotImplementedError(
                f"Unsupported installer type: {installer_type}"
            )