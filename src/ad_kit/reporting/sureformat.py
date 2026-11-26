"""Export integration findings in SureFormat XML."""

import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path

from ad_kit.core.console import print_warning
from ad_kit.core.finding import Finding
from ad_kit.reporting.json import integration_finding

FINDING_MAP = {
    "SMB-001": "SC-7704",
    "SMB-002": "SC-3576",
    "SMB-003": "SC-1909",
    "SMB-004": "SC-7367",
    "LDAP-001": "SC-6080",
    "LDAP-002": "SC-6643",
    "LDAP-003": "SC-1000",
    "LDAPINFO-001": "SC-9182",
    "DNS-001": "SC-7565",
    "MAQ-001": "SC-5915",
    "COERCE-001": "SC-9018",
    "PASS-001": "SC-1932",
    "PASS-002": "SC-9249",
    "PASS-003": "SC-10675",
    "ASREP-001": "SC-3550",
    "ASREP-002": "SC-3550",
    "KERB-001": "SC-3301",
    "KERB-002": "SC-3301",
    "ADCS-ESC1": "SC-3570",
    "ADCS-ESC8": "SC-3570",
    "ADCS-ESC15": "SC-3570",
    "NOPAC-001": "SC-3704",
    "PRE2K-001": "SC-7136",
    "DELEG-001": "SC-9479",
    "PRIV-001": "SC-10674",
    "PRIV-002": "SC-10700",
    "PRIV-003": "SC-10676",
    "PRIV-004": "SC-4958",
    "PRIV-005": "SC-6642",
    "LA-002": "SC-6642",
}

DC_FINDING_IDS = {
    "LDAP-001",
    "LDAP-002",
    "LDAP-003",
    "COERCE-001",
    "NOPAC-001",
}


class DCExportError(ValueError):
    """A DC finding cannot be reliably assigned to an IP address."""


def dc_inventory(session: dict) -> list[tuple[str, str]]:
    """Load paired DC identities, including sessions created by older versions."""
    controllers = session.get("dc_controllers")
    if controllers is None:
        hostnames, ips = session.get("dc_hostnames"), session.get("dc_ips")
        if (
            not isinstance(hostnames, list)
            or not isinstance(ips, list)
            or len(hostnames) != len(ips)
        ):
            raise DCExportError("DC hostname/IP pairs are missing. Run 'ad-kit enum' again.")
        controllers = [{"hostname": host, "ip": ip} for host, ip in zip(hostnames, ips)]
    if not isinstance(controllers, list) or not controllers:
        raise DCExportError("DC hostname/IP pairs are missing. Run 'ad-kit enum' again.")

    inventory: list[tuple[str, str]] = []
    seen_hosts: set[str] = set()
    seen_ips: set[str] = set()
    for controller in controllers:
        if not isinstance(controller, dict):
            raise DCExportError("Invalid DC inventory. Run 'ad-kit enum' again.")
        hostname, address = controller.get("hostname"), controller.get("ip")
        if not isinstance(hostname, str) or not hostname.strip().rstrip("."):
            raise DCExportError("Invalid DC hostname in session metadata. Run 'ad-kit enum' again.")
        try:
            if not isinstance(address, str):
                raise ValueError("IP address must be a string")
            ip = str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise DCExportError(
                "Invalid DC IP in session metadata. Run 'ad-kit enum' again."
            ) from exc
        hostname = hostname.strip().rstrip(".")
        key = hostname.casefold()
        if key in seen_hosts or ip in seen_ips:
            raise DCExportError("Ambiguous DC hostname/IP mapping. Run 'ad-kit enum' again.")
        seen_hosts.add(key)
        seen_ips.add(ip)
        inventory.append((hostname, ip))
    return inventory


def _append_item(
    root: ET.Element, hostname: str, ip: str, findings: list[dict[str, str]]
) -> None:
    item = ET.SubElement(root, "item", ipaddress=ip, hostname=hostname)
    services = ET.SubElement(item, "services")
    service = ET.SubElement(services, "service", name="", port="", protocol="tcp")
    vulnerabilities = ET.SubElement(service, "vulnerabilities")

    mapped_vulnerabilities: dict[str, ET.Element] = {}
    for finding in findings:
        vulnerability_id = FINDING_MAP.get(finding["id"])
        if not vulnerability_id:
            print_warning(f"No SureFormat mapping found for finding: {finding['id']}")
            continue
        if vulnerability_id in mapped_vulnerabilities:
            information = mapped_vulnerabilities[vulnerability_id]
            information.text = (information.text or "") + "\n" + finding["description"]
        else:
            vulnerability = ET.SubElement(vulnerabilities, "vulnerability", id=vulnerability_id)
            information = ET.SubElement(vulnerability, "information")
            information.text = finding["description"]
            mapped_vulnerabilities[vulnerability_id] = information


def write_findings(
    path: Path,
    hostname: str,
    findings: list[dict[str, str]],
    *,
    controllers: list[tuple[str, str]] | None = None,
    dc_findings: list[Finding] | None = None,
) -> None:
    """Write domain findings and, optionally, per-controller findings."""
    root = ET.Element("items", source="SureFormat", version="1.0.0")
    _append_item(root, hostname, "", findings)
    if controllers is not None:
        aliases: dict[str, set[int]] = {}
        for index, (dc_hostname, ip) in enumerate(controllers):
            host = dc_hostname.casefold().rstrip(".")
            for alias in (host, host.split(".")[0], ip):
                aliases.setdefault(alias, set()).add(index)

        per_dc: list[list[dict[str, str]]] = [[] for _ in controllers]
        for finding in dc_findings or []:
            if not finding.affected_assets:
                raise DCExportError(f"Finding {finding.id} has no affected DCs; cannot export it.")
            matched: set[int] = set()
            for asset in finding.affected_assets:
                key = asset.strip().casefold().rstrip(".")
                try:
                    key = str(ipaddress.ip_address(key))
                except ValueError:
                    pass
                matches = aliases.get(key, set())
                if len(matches) != 1:
                    raise DCExportError(
                        f"Cannot uniquely match DC '{asset}' for {finding.id} to session IPs."
                    )
                matched.update(matches)
            for index in sorted(matched):
                per_dc[index].append(integration_finding(finding))
        for (dc_hostname, ip), dc_items in zip(controllers, per_dc):
            if dc_items:
                dc_items.sort(
                    key=lambda item: (item["id"].casefold(), item["description"].casefold())
                )
                _append_item(root, dc_hostname, ip, dc_items)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(path, encoding="utf-8", xml_declaration=False)
