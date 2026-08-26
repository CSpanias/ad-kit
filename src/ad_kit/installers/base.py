"""
Base installer definitions.

This module defines the abstract interface that all installer
implementations must follow.
"""

from abc import ABC, abstractmethod

from ad_kit.models import Tool


class Installer(ABC):
    """
    Abstract base class for all installer implementations.
    """

    @abstractmethod
    def install(self, tool: Tool) -> None:
        """
        Install a tool.

        Args:
            tool: Tool definition to install.
        """
        raise NotImplementedError