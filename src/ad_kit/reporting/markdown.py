"""
Markdown report generation.

This module generates Markdown reports from a collection
of findings identified during an Active Directory
assessment.
"""

from pathlib import Path

from ad_kit.core.finding import Finding


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

            lines.append(
                f"**Severity:** {finding.severity}"
            )
            lines.append("")

            lines.append("### Commentary")
            lines.append("")
            lines.append(finding.commentary)
            lines.append("")

            lines.append("### Remediation")
            lines.append("")
            lines.append(finding.remediation)
            lines.append("")

            if finding.affected_assets:

                lines.append("### Affected Assets")
                lines.append("")

                for asset in finding.affected_assets:
                    lines.append(f"- {asset}")

                lines.append("")

            if finding.evidence:

                lines.append("### Evidence")
                lines.append("")

                for item in finding.evidence:
                    lines.append(f"- {item}")

                lines.append("")

            if finding.references:

                lines.append("### References")
                lines.append("")

                for reference in finding.references:
                    lines.append(f"- {reference}")

                lines.append("")

    output_file.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )