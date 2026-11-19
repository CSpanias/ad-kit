"""Export integration findings in SureFormat XML."""

import xml.etree.ElementTree as ET
from pathlib import Path

from ad_kit.core.console import print_warning

FINDING_MAP = {
    "smb-signing-not-enforced": "SC-7704",
    "smbv1-enabled": "SC-3576",
    "smb-null-sessions": "SC-1909",
    "weak-smb-share-permissions": "SC-7367",
    "ldap-signing-not-enforced": "SC-6080",
    "ldap-channel-binding-not-enforced": "SC-6643",
    "ldap-null-binds": "SC-1000",
    "dns-record-creation": "SC-7565",
    "maq-set-to-10": "SC-5915",
    "dc-coercion": "SC-9018",
    "weak-password-policy": "SC-1932",
    "password-not-required": "SC-9811",
    "as-rep-roasting": "SC-3550",
    "kerberoasting": "SC-3301",
    "ad-cs-esc1": "SC-3570",
    "ad-cs-esc8": "SC-3570",
    "ad-cs-esc15": "SC-3570",
    "nopac": "SC-3704",
    "pre2k": "SC-7136",
    "unconstrained-delegation": "SC-9479",
}

DC_FINDING_IDS = {
    "ldap-signing-not-enforced",
    "ldap-channel-binding-not-enforced",
    "ldap-null-binds",
    "dc-coercion",
    "nopac",
}


def write_findings(path: Path, hostname: str, findings: list[dict[str, str]]) -> None:
    """Write mapped findings with the same structure as the SureCloud adapter."""
    root = ET.Element("items", source="SureFormat", version="1.0.0")
    item = ET.SubElement(root, "item", ipaddress="", hostname=hostname)
    services = ET.SubElement(item, "services")
    service = ET.SubElement(services, "service", name="", port="", protocol="tcp")
    vulnerabilities = ET.SubElement(service, "vulnerabilities")

    for finding in findings:
        vulnerability_id = FINDING_MAP.get(finding["id"])
        if not vulnerability_id:
            print_warning(f"No SureFormat mapping found for finding: {finding['id']}")
            continue
        vulnerability = ET.SubElement(vulnerabilities, "vulnerability", id=vulnerability_id)
        ET.SubElement(vulnerability, "information").text = finding["description"]

    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(path, encoding="utf-8", xml_declaration=False)
