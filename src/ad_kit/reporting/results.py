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
    session: dict[str, object] | None = None,
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

    host_findings = []
    domain_findings = []
    for finding in _findings:
        if finding.id in sureformat.HOST_FINDING_IDS and finding.affected_assets:
            host_findings.append(finding)
        else:
            if finding.id in sureformat.HOST_FINDING_IDS:
                print_warning(
                    f"Finding {finding.id} has no affected hosts; exporting under domain."
                )
            domain_findings.append(json.integration_finding(finding))
    domain_findings.sort(key=lambda item: (item["id"].casefold(), item["description"].casefold()))
    controllers = []
    if host_findings:
        try:
            controllers = sureformat.dc_inventory(session or {})
        except sureformat.DCExportError as exc:
            print_warning(f"Cannot use DC inventory: {exc}")
    dns_server = (session or {}).get("dc_ip")
    if dns_server is not None and not isinstance(dns_server, str):
        print_warning("Cannot use the session DNS server: its IP is not a string.")
        dns_server = None
    sureformat.write_findings(
        directory / f"{basename}.xml", domain.lower(), domain_findings,
        controllers=controllers, host_findings=host_findings,
        dns_server=dns_server,
    )
