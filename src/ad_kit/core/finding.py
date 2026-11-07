"""
Finding model.

This module defines the canonical finding structure used throughout AD-Kit. 
Finding definitions are loaded from YAML files, populated during assessment
checks, and consumed by reporting modules.
"""

from dataclasses import dataclass, field
from copy import deepcopy


@dataclass
class Finding:
    """
    Represents a security finding identified during an
    Active Directory assessment.

    Attributes:
        id:
            Unique finding identifier.

        title:
            Human-readable finding title.

        commentary:
            Description of the identified security
            issue and its potential impact.

        remediation:
            Recommended remediation guidance.

        affected_assets:
            Assets affected by the finding.

        references:
            External references and supporting
            documentation.
    """

    id: str
    title: str

    commentary: str
    remediation: str

    affected_assets: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


    def copy(self) -> "Finding":
        """
        Create a deep copy of the finding.

        This allows a finding definition to be loaded
        from a template and then modified independently
        without affecting the original definition.
        """
        return deepcopy(self)