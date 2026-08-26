"""
Custom exceptions used throughout AD-Kit.
"""


class ADKitError(Exception):
    """
    Base exception for all AD-Kit errors.
    """

class InstallationError(ADKitError):
    """
    Raised when a tool installation fails.
    """

    def __init__(
        self,
        tool_name: str,
        reason: str,
    ) -> None:
        self.tool_name = tool_name
        self.reason = reason

        super().__init__(reason)


class ToolNotFoundError(ADKitError):
    """
    Raised when a requested tool does not exist in the registry.
    """


class InstallationError(ADKitError):
    """
    Raised when a tool installation fails.

    Attributes:
        tool_name: Name of the tool that failed.
        reason: Human-readable explanation of the failure.
    """

    def __init__(
        self,
        tool_name: str,
        reason: str,
    ) -> None:
        self.tool_name = tool_name
        self.reason = reason

        super().__init__(f"Failed to install '{tool_name}': {reason}")