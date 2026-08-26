"""
Data models used by AD-Kit.
"""

from dataclasses import dataclass


@dataclass(slots=True)
class Tool:
    """
    Represents a tool definition from the registry.

    Attributes:
        name: Unique tool name.
        installer: Installer type used to install the tool.
        source: Source used by the installer.
        check_command: Executable used for installation checks.
        description: Human-readable description.
    """

    name: str
    installer: str
    description: str

    source: str | None = None
    repo: str | None = None
    binary_name: str | None = None
    check_command: str | None = None
    asset_pattern: str | None = None