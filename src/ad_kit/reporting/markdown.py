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


def format_evidence(finding: Finding, heading: str) -> str:
    if finding.show_evidence and (finding.evidence or finding.evidence_table):
        parts = [f"{heading} Evidence"]
        if finding.evidence_introduction:
            parts.append(finding.evidence_introduction)
        if finding.evidence_table:
            table = finding.evidence_table

            def cell(value: str) -> str:
                return (value.replace("\\", "\\\\").replace("|", "\\|")
                        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        .replace("\r", " ").replace("\n", " "))

            rows = [table.columns, tuple("---" for _ in table.columns), *table.rows]
            parts.extend([
                table.introduction,
                "\n".join("| " + " | ".join(cell(value) for value in row) + " |"
                          for row in rows),
            ])
        if finding.evidence:
            parts.append("\n".join(
                f"{index}. {item}" for index, item in enumerate(finding.evidence, start=1)
            ))
        return "\n\n".join(parts)
    return ""


def format_finding_sections(finding: Finding, *, heading_level: int = 1) -> dict[str, str]:
    """Format independently copyable sections, including their related lists."""
    heading = "#" * heading_level
    subheading = "#" * (heading_level + 2)
    sections = {}

    evidence = format_evidence(finding, subheading if finding.evidence_in_commentary else heading)
    if finding.commentary or finding.commentary_note or (
        finding.show_affected_assets and finding.affected_assets
    ) or (finding.evidence_in_commentary and evidence):
        parts = [f"{heading} Commentary", format_paragraphs(finding.commentary)]
        if finding.commentary_note:
            parts.append(f"**Note:** {format_paragraphs(finding.commentary_note)}")
        if finding.show_affected_assets and finding.affected_assets:
            parts.extend([
                f"{subheading} Affected Assets",
                "\n".join(f"- {asset}" for asset in finding.affected_assets),
            ])
        if finding.evidence_in_commentary and evidence:
            parts.append(evidence)
        sections["Commentary"] = "\n\n".join(part for part in parts if part)

    if evidence and not finding.evidence_in_commentary:
        sections["Evidence"] = evidence

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