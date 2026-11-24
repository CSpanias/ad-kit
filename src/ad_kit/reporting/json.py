"""
JSON findings export.

Exports assessment findings in a machine-readable format suitable for
integration with external reporting platforms:

    {"findings": [{"id": ..., "description": ...}, ...]}
"""

import json
from pathlib import Path

from ad_kit.core.finding import Finding
from ad_kit.reporting.markdown import format_paragraphs

_findings: list[dict[str, str]] = []


def collect(findings: list[Finding]) -> None:
    """Collect all findings using their YAML IDs and commentary."""
    for finding in findings:
        description = format_paragraphs(finding.commentary).strip()
        if finding.commentary_note:
            note = "Note: " + format_paragraphs(finding.commentary_note).strip()
            description = "\n\n".join(part for part in (description, note) if part)
        _findings.append({"id": finding.id, "description": description})


def reset() -> None:
    """Clear collected findings before starting a new run."""
    _findings.clear()


def get_findings() -> list[dict[str, str]]:
    """Return collected integration findings in a stable order."""
    return sorted(
        _findings,
        key=lambda item: (item["id"].casefold(), item["description"].casefold()),
    )


def write_findings(path: str | Path) -> None:
    """Write the collected findings to a JSON file."""
    output = {"findings": get_findings()}
    Path(path).write_text(
        json.dumps(output, indent=4) + "\n",
        encoding="utf-8",
    )
