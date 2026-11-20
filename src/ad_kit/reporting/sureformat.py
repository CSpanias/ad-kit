"""Export integration findings in SureFormat XML."""

import xml.etree.ElementTree as ET
from pathlib import Path

from ad_kit.core.console import print_warning

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
    "PRIV-003": "SC-10676",
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


def write_findings(path: Path, hostname: str, findings: list[dict[str, str]]) -> None:
    """Write mapped findings with the same structure as the SureCloud adapter."""
    root = ET.Element("items", source="SureFormat", version="1.0.0")
    item = ET.SubElement(root, "item", ipaddress="", hostname=hostname)
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

    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(path, encoding="utf-8", xml_declaration=False)
