"""Collect findings from checks and write the requested reports."""

from pathlib import Path

from ad_kit.core.console import print_warning
from ad_kit.core.finding import Finding
from ad_kit.core.util import count_form
from ad_kit.reporting import html, json, sureformat

_findings: list[Finding] = []
_incomplete: list[str] = []


def reset() -> None:
    """Start a new reporting run."""
    _findings.clear()
    _incomplete.clear()
    json.reset()


def record_findings(findings: list[Finding]) -> None:
    """Collect all findings for the HTML and JSON exports."""
    _findings.extend(findings)
    json.collect(findings)


def record_incomplete(
    check: str, host: str, reason: str, *, notify: bool = True
) -> None:
    """Record and display a check that could not be completed."""
    entry = f"{check} - {host}: {reason}" if host else f"{check}: {reason}"
    _incomplete.append(entry)
    if notify:
        print_warning(f"Incomplete: {entry}")


def write_reports(
    directory: Path, *, run_name: str = "all", domain: str | None = None,
    dc_controllers: list[tuple[str, str]] | None = None,
) -> None:
    """Write the full HTML report and the selected integration export."""
    basename = f"ad-kit_findings_{run_name}"
    html.write_report(_findings, directory / f"{basename}.html", _incomplete)
    if _incomplete:
        print_warning(
            f"Assessment incomplete: {len(_incomplete)} coverage "
            f"{count_form(len(_incomplete), 'gap', 'gaps')}. "
            "See the HTML report for details."
        )
    if domain is None:
        json.write_findings(directory / f"{basename}.json")
        return

    findings = json.get_findings()
    domain_findings = [
        f for f in findings if dc_controllers is None or f["id"] not in sureformat.DC_FINDING_IDS
    ]
    dc_findings = [f for f in _findings if f.id in sureformat.DC_FINDING_IDS]
    sureformat.write_findings(
        directory / f"{basename}.xml", domain.lower(), domain_findings,
        controllers=dc_controllers, dc_findings=dc_findings,
    )
