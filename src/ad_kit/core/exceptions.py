"""
Custom exceptions used throughout AD-Kit.
"""


class ADKitError(Exception):
    """
    Base exception for all AD-Kit errors.
    """

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


class CheckExecutionError(ADKitError):
    """
    Raised when an assessment check's command cannot be executed.

    This is raised when the underlying tool or module (for example a NetExec
    module that has not been merged upstream yet) is unavailable, the command
    binary is missing, or the command exits with a non-zero return code.

    Attributes:
        name: Evidence name of the failed check.
        command: The (redacted) command that was executed.
        returncode: Exit code of the command, or None if it never started.
        stderr: Redacted standard error output, if any.
    """

    def __init__(
        self,
        name: str,
        command: list[str],
        returncode: int | None = None,
        stderr: str | None = None,
    ) -> None:
        self.name = name
        self.command = command
        self.returncode = returncode
        self.stderr = (stderr or "").strip()

        reason_lines = [
            line.strip()
            for line in self.stderr.splitlines()
            if line.strip()
        ]
        reason = reason_lines[-1] if reason_lines else ""

        message = f"Check '{name}' did not run"
        if reason:
            message += f": {reason}"
        elif returncode is not None:
            message += f" (exit code {returncode})"

        super().__init__(message)