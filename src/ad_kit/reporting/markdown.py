"""
Markdown report generation.

This module generates Markdown reports from a collection
of findings identified during an Active Directory
assessment.
"""

from pathlib import Path

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


def _format_remediation(text: str) -> str:
    """
    Preserve paragraphs while collapsing wrapped bullet items into single-line 
    Markdown list entries.
    """

    lines = text.splitlines()

    output = []
    current_bullet = None

    for line in lines:
        stripped = line.strip()

        if not stripped:
            if current_bullet:
                output.append(current_bullet)
                current_bullet = None

            output.append("")
            continue

        if stripped.startswith("- "):
            if current_bullet:
                output.append(current_bullet)

            current_bullet = stripped

        elif current_bullet:
            current_bullet += f" {stripped}"

        else:
            output.append(stripped)

    if current_bullet:
        output.append(current_bullet)

    return "\n".join(output)


def write_markdown_report(
    findings: list[Finding],
    output_file: Path,
) -> None:
    """
    Generate a Markdown findings report.

    Args:
        findings:
            Findings to include.

        output_file:
            Report output path.
    """

    lines: list[str] = []

    lines.append("# Active Directory Assessment Findings")
    lines.append("")

    if not findings:
        lines.append("No findings identified.")
        lines.append("")
    else:

        for finding in findings:

            lines.append(
                f"## {finding.id} - {finding.title}"
            )
            lines.append("")

            lines.append("### Commentary")
            lines.append("")
            lines.append(format_paragraphs(finding.commentary))
            lines.append("")

            if finding.evidence:

                lines.append("### Evidence")
                lines.append("")

                for evidence in finding.evidence:
                    lines.append(f"- {evidence}")

                lines.append("")

            lines.append("### Remediation")
            lines.append("")
            lines.append(_format_remediation(finding.remediation))
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

    output_file.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )