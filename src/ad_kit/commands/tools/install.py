"""
Install command implementation.
"""

from ad_kit.core.console import print_error, print_info
from ad_kit.core.exceptions import InstallationError
from ad_kit.installers.factory import get_installer
from ad_kit.registry import ToolRegistry


def install_tool(tool_name: str) -> None:
    """
    Install a tool or all registered tools.

    Args:
        tool_name: Tool name or the special value "all".
    """
    if tool_name.lower() == "all":
        install_all_tools()
        return

    registry = ToolRegistry()

    if not registry.tool_exists(tool_name):
        available_tools = ", ".join(
            tool.name for tool in registry.get_all_tools()
        )

        print_error(f"Unknown tool: {tool_name}")
        print_info(f"Available tools: {available_tools}")

        return

    tool = registry.get_tool(tool_name)
    installer = get_installer(tool.installer)

    try:
        installer.install(tool)

    except InstallationError as exc:
        print_error(f"Failed to install {exc.tool_name}: {exc.reason}")

        return

    except Exception as exc:
        print_error(str(exc))


def install_all_tools() -> None:
    """
    Install all tools defined in the registry.

    Installation failures are reported but do not stop the
    installation of remaining tools.
    """
    registry = ToolRegistry()

    successful = 0
    failed = 0

    print_info("Installing all registered tools...")

    for tool in registry.get_all_tools():
        try:
            installer = get_installer(tool.installer)
            installer.install(tool)
            successful += 1

        except Exception as exc:
            print_error(f"Failed to install {tool.name}: {exc}")

            failed += 1

    print_info(
        f"Installation completed. "
        f"Success: {successful}, Failed: {failed}"
    )