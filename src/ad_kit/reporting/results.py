"""Collect findings from checks and write the requested reports."""

from pathlib import Path

from ad_kit.core.finding import Finding
from ad_kit.reporting import html, json, sureformat

_findings: list[Finding] = []


def reset() -> None:
    """Start a new reporting run."""
    _findings.clear()
    json.reset()


def record_findings(findings: list[Finding]) -> None:
    """Collect all findings for the HTML and JSON exports."""
    _findings.extend(findings)
    json.collect(findings)


def write_reports(directory: Path, *, domain: str | None = None, dc: str | None = None) -> None:
    """Write the full HTML report and the selected integration export."""
    html.write_report(_findings, directory / "ad-kit_findings.html")
    if domain is None:
        json.write_findings(directory / "ad-kit_findings.json")
        return

    findings = json.get_findings()
    domain_findings = [
        f for f in findings if dc is None or f["id"] not in sureformat.DC_FINDING_IDS
    ]
    sureformat.write_findings(directory / "ad-kit_findings.xml", domain, domain_findings)
    if dc is not None:
        dc_findings = [f for f in findings if f["id"] in sureformat.DC_FINDING_IDS]
        sureformat.write_findings(directory / "ad-kit_findings-dc.xml", dc, dc_findings)
