"""
Markdown formatting for copyable findings.

This module formats findings identified during an Active Directory assessment.
"""

from ad_kit.core.finding import Finding


def format_paragraphs(
    text: str,
) -> str:
    """
    Convert wrapped YAML text into readable report paragraphs.

    Wrapped lines within a paragraph are joined into a single line while
    preserving paragraph breaks and Markdown lists.
    """

    paragraphs = []

    for paragraph in text.split("\n\n"):

        lines = paragraph.splitlines()

        # Markdown list
        if lines and lines[0].lstrip().startswith("-"):

            items = []
            current = ""

            for line in lines:
                stripped = line.strip()

                if stripped.startswith("-"):
                    if current:
                        items.append(current)
                    current = stripped
                else:
                    current += f" {stripped}"

            if current:
                items.append(current)

            paragraphs.append("\n".join(items))
            continue

        paragraphs.append(
            " ".join(
                line.strip()
                for line in lines
            )
        )

    return "\n\n".join(paragraphs)


def format_finding_sections(finding: Finding, *, heading_level: int = 1) -> dict[str, str]:
    """Format independently copyable sections, including their related lists."""
    heading = "#" * heading_level
    subheading = "#" * (heading_level + 2)
    sections = {}

    if finding.commentary or finding.affected_assets:
        parts = [f"{heading} Commentary", format_paragraphs(finding.commentary)]
        if finding.affected_assets:
            parts.extend([
                f"{subheading} Affected Assets",
                "\n".join(f"- {asset}" for asset in finding.affected_assets),
            ])
        sections["Commentary"] = "\n\n".join(part for part in parts if part)

    if finding.evidence:
        evidence = "\n".join(
            f"{index}. {item}" for index, item in enumerate(finding.evidence, start=1)
        )
        sections["Evidence"] = f"{heading} Evidence\n\n{evidence}"

    if finding.remediation or finding.references:
        parts = [f"{heading} Remediation", format_paragraphs(finding.remediation)]
        if finding.references:
            parts.extend([
                f"{subheading} References",
                "\n".join(f"- [{reference}]({reference})" for reference in finding.references),
            ])
        sections["Remediation"] = "\n\n".join(part for part in parts if part)

    return sections


def format_findings(findings: list[Finding]) -> str:
    """Format findings as Markdown without a report-level heading."""
    formatted = []
    for finding in findings:
        sections = format_finding_sections(finding, heading_level=3)
        formatted.append(
            "\n\n".join([f"## {finding.id} - {finding.title}", *sections.values()])
        )
    return "\n\n".join(formatted) + ("\n" if formatted else "")