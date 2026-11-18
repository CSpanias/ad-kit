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


def format_findings(findings: list[Finding]) -> str:
    """Format findings as Markdown without a report-level heading."""
    lines: list[str] = []

    for finding in findings:

        lines.append(f"## {finding.id} - {finding.title}")
        lines.append("")

        lines.append("### Commentary")
        lines.append("")
        lines.append(format_paragraphs(finding.commentary))
        lines.append("")

        if finding.evidence:

            lines.append("### Evidence")
            lines.append("")

            for index, evidence in enumerate(finding.evidence, start=1):
                lines.append(f"{index}. {evidence}")

            lines.append("")

        lines.append("### Remediation")
        lines.append("")
        lines.append(format_paragraphs(finding.remediation))
        lines.append("")

        if finding.affected_assets:

            lines.append("### Affected Assets")
            lines.append("")

            for asset in finding.affected_assets:

                lines.append(f"- {asset}")

            lines.append("")

        if finding.references:

            lines.append("### References")
            lines.append("")

            for reference in finding.references:

                lines.append(f"- [{reference}]({reference})")

            lines.append("")

    return "\n".join(lines)