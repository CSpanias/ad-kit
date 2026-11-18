"""Collect findings from checks and write the requested reports."""

from pathlib import Path

from ad_kit.core.finding import Finding
from ad_kit.reporting import html, json, markdown

_findings: list[Finding] = []
_markdown_enabled = False


def reset(*, markdown_enabled: bool = False) -> None:
    """Start a new reporting run."""
    global _markdown_enabled
    _findings.clear()
    json.reset()
    _markdown_enabled = markdown_enabled


def record_findings(findings: list[Finding], output_file: Path) -> None:
    """Collect all findings and optionally write the per-check Markdown."""
    _findings.extend(findings)
    json.collect(findings)
    if _markdown_enabled:
        markdown.write_markdown_report(findings, output_file)


def write_reports(directory: Path) -> None:
    """Write the full HTML report and the integration JSON export."""
    html.write_report(_findings, directory / "ad-kit_findings.html")
    json.write_findings(directory / "ad-kit_findings.json")
