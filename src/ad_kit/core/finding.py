"""
Finding model.

This module defines the canonical finding structure used throughout AD-Kit. 
Finding definitions are loaded from YAML files, populated during assessment
checks, and consumed by reporting modules.
"""

from dataclasses import dataclass, field


@dataclass
class EvidenceTable:
    introduction: str
    columns: tuple[str, ...]
    rows: list[tuple[str, ...]]


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

        show_affected_assets:
            Whether the affected asset list is displayed in reports.

        show_evidence:
            Whether the evidence section is displayed in reports.

        evidence_in_commentary:
            Whether evidence is displayed within commentary instead of separately.

        commentary_note:
            Optional note displayed after the commentary.

        references:
            External references and supporting
            documentation.

        evidence_table:
            Optional tabular evidence with an introduction.

        evidence_introduction:
            Optional introduction to the evidence list.
    """

    id: str
    title: str

    commentary: str
    remediation: str

    affected_assets: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    evidence_table: EvidenceTable | None = None
    evidence_introduction: str = ""
    show_affected_assets: bool = True
    commentary_note: str = ""
    show_evidence: bool = True
    evidence_in_commentary: bool = False