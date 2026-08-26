"""
Registry functionality for AD-Kit.

This module is responsible for loading tool definitions from the
tools.yaml file and providing access to tool information throughout
the application.
"""

from pathlib import Path
from typing import Any

import yaml

from ad_kit.models import Tool


class ToolRegistry:
    """
    Manage the loading and retrieval of tool definitions.

    Tool definitions are stored in YAML format and converted into
    Tool objects when loaded.

    Example:
        registry = ToolRegistry()
        netexec = registry.get_tool("netexec")
    """

    def __init__(self) -> None:
        """
        Initialize the registry and load tool definitions.
        """
        self._tools: dict[str, Tool] = {}
        self._load_tools()


    def _validate_tool_config(
        self,
        tool_name: str,
        config: dict[str, Any],
    ) -> None:
        """
        Validate a tool configuration loaded from the registry.

        Args:
            tool_name: Name of the tool being validated.
            config: Tool configuration dictionary.

        Raises:
            ValueError: If required fields are missing.
        """

        if "installer" not in config:
            raise ValueError(
                f"Tool '{tool_name}' is missing required field: 'installer'"
            )

        installer_type = config["installer"]

        if installer_type == "uv":
            required_fields = [
                "source",
                "check_command",
            ]

        elif installer_type == "github_release":
            required_fields = [
                "repo",
                "asset_pattern",
                "binary_name",
                "check_command",
            ]

        else:
            raise ValueError(f"Unsupported installer type: '{installer_type}'")

        for field in required_fields:
            if field not in config:
                raise ValueError(
                    f"Tool '{tool_name}' is missing required field: '{field}'"
                )


    def _load_tools(self) -> None:
        """
        Load tool definitions from tools.yaml.

        Raises:
            FileNotFoundError: If tools.yaml cannot be found.
            ValueError: If the YAML structure is invalid.
        """
        data_path = (
            Path(__file__).parent
            / "data"
            / "tools.yaml"
        )

        if not data_path.exists():
            raise FileNotFoundError(
                f"Tool registry file not found: {data_path}"
            )

        with data_path.open("r", encoding="utf-8") as file:
            raw_tools: dict[str, dict[str, Any]] = (
                yaml.safe_load(file) or {}
            )

        for name, config in raw_tools.items():
            self._validate_tool_config(name, config)

            self._tools[name] = Tool(
                name=name,
                installer=config["installer"],
                source=config.get("source"),
                repo=config.get("repo"),
                binary_name=config.get("binary_name"),
                check_command=config.get("check_command"),
                description=config.get(
                    "description",
                    "No description provided.",
                ),
                asset_pattern=config.get("asset_pattern"),
            )


    def get_tool(self, name: str) -> Tool:
        """
        Retrieve a tool by name.

        Args:
            name: Name of the tool.

        Returns:
            A Tool instance.

        Raises:
            KeyError: If the tool does not exist.
        """
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(
                f"Tool '{name}' does not exist."
            ) from exc


    def get_all_tools(self) -> list[Tool]:
        """
        All registered tools.

        Returns:
            List of Tool objects sorted alphabetically.
        """
        return sorted(
            self._tools.values(),
            key=lambda tool: tool.name.lower(),
        )


    def tool_exists(self, name: str) -> bool:
        """
        Check whether a tool exists in the registry.

        Args:
            name: Tool name.

        Returns:
            True if the tool exists, otherwise False.
        """
        return name in self._tools