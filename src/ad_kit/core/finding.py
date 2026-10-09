"""
Finding model.

This module defines the canonical finding structure used
throughout AD-Kit. Findings are produced by assessment
checks and consumed by reporting modules.
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

        severity:
            Assigned risk rating.

        description:
            High-level overview of the issue.

        impact:
            Potential security implications.

        recommendation:
            Recommended remediation guidance.

        affected_assets:
            Assets affected by the finding.

        evidence:
            Evidence supporting the finding.

        references:
            External references and guidance.
    """

    id: str
    title: str
    severity: str

    description: str
    impact: str
    recommendation: str

    affected_assets: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def copy(self) -> "Finding":
        """
        Create an independent copy of the finding.
        """
        return deepcopy(self)