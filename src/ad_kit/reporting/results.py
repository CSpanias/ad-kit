"""Collect findings from checks and write the requested reports."""

from pathlib import Path

from ad_kit.core.finding import Finding
from ad_kit.reporting import html, json

_findings: list[Finding] = []


def reset() -> None:
    """Start a new reporting run."""
    _findings.clear()
    json.reset()


def record_findings(findings: list[Finding]) -> None:
    """Collect all findings for the HTML and JSON exports."""
    _findings.extend(findings)
    json.collect(findings)


def write_reports(directory: Path) -> None:
    """Write the full HTML report and the integration JSON export."""
    html.write_report(_findings, directory / "ad-kit_findings.html")
    json.write_findings(directory / "ad-kit_findings.json")
