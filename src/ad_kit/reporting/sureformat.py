"""Export integration findings in SureFormat XML."""

import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path

import dns.exception
import dns.resolver

from ad_kit.core.console import print_warning
from ad_kit.core.finding import Finding
from ad_kit.core.util import parallel_items
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

HOST_FINDING_IDS = {
    "LDAP-001",
    "LDAP-002",
    "LDAP-003",
    "COERCE-001",
    "NOPAC-001",
    "SMB-001",
    "SMB-002",
    "SMB-003",
    "SMB-004",
    "LA-002",
}


class DCExportError(ValueError):
    """A DC finding cannot be reliably assigned to an IP address."""


def dc_inventory(session: dict[str, object]) -> list[tuple[str, str]]:
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


def _resolve_host(hostname: str, domain: str, dns_server: str | None) -> str:
    if not dns_server:
        raise ValueError("the session has no DNS server IP")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [str(ipaddress.ip_address(dns_server))]
    resolver.timeout = 2
    resolver.lifetime = 3
    name = hostname if "." in hostname else f"{hostname}.{domain}"
    addresses: set[str] = set()
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(name, record_type, search=False)
        except dns.resolver.NoAnswer:
            continue
        addresses.update(str(ipaddress.ip_address(record.address)) for record in answer)
    if len(addresses) != 1:
        raise ValueError(f"DNS returned {len(addresses)} IP addresses")
    return next(iter(addresses))


def write_findings(
    path: Path,
    hostname: str,
    findings: list[dict[str, str]],
    *,
    controllers: list[tuple[str, str]] | None = None,
    host_findings: list[Finding] | None = None,
    dns_server: str | None = None,
) -> None:
    """Write domain findings and, optionally, per-host findings."""
    root = ET.Element("items", source="SureFormat", version="1.0.0")
    _append_item(root, hostname, "", findings)
    if host_findings:
        controllers = controllers or []
        aliases: dict[str, set[int]] = {}
        for index, (dc_hostname, ip) in enumerate(controllers):
            host = dc_hostname.casefold().rstrip(".")
            for alias in (host, host.split(".")[0], ip):
                aliases.setdefault(alias, set()).add(index)

        hosts: dict[str, tuple[str, str, list[dict[str, str]]]] = {}
        to_resolve: list[str] = []
        for finding in host_findings:
            matched: set[str] = set()
            for asset in finding.affected_assets:
                key = asset.strip().casefold().rstrip(".")
                if not key:
                    raise ValueError(f"Finding {finding.id} has an empty affected host.")
                try:
                    key = str(ipaddress.ip_address(key))
                except ValueError:
                    pass
                matches = aliases.get(key, set())
                if len(matches) == 1:
                    dc_hostname, ip = controllers[next(iter(matches))]
                    key = dc_hostname.casefold().rstrip(".")
                    hosts.setdefault(key, (dc_hostname, ip, []))
                else:
                    if not matches and "." not in key and ":" not in key:
                        key = f"{key}.{hostname.casefold().rstrip('.')}"
                if key not in hosts:
                    try:
                        ip = str(ipaddress.ip_address(key))
                        hosts[key] = ("", ip, [])
                    except ValueError:
                        if matches:
                            reason = "the name matches multiple domain controllers"
                            print_warning(f"Cannot determine IP for host '{asset}': {reason}.")
                        else:
                            to_resolve.append(key)
                        hosts[key] = (asset.strip().rstrip("."), "", [])
                matched.add(key)
            for key in matched:
                hosts[key][2].append(integration_finding(finding))

        def resolve(key: str) -> tuple[str, str]:
            try:
                return _resolve_host(key, hostname, dns_server), ""
            except (dns.exception.DNSException, ValueError, OSError) as exc:
                return "", str(exc)

        if to_resolve:
            resolved = parallel_items(to_resolve, "Resolving report hosts", resolve)
            for key, (ip, reason) in zip(to_resolve, resolved):
                host, _, host_items = hosts[key]
                if not ip:
                    print_warning(f"Cannot determine IP for host '{host}': {reason}.")
                hosts[key] = (host, ip, host_items)

        by_ip: dict[str, list[str]] = {}
        for key, (_, ip, _) in hosts.items():
            if ip:
                by_ip.setdefault(ip, []).append(key)
        for ip, keys in by_ip.items():
            if len(keys) > 1:
                known = {dc.casefold().rstrip(".") for dc, _ in controllers}
                authoritative = [key for key in keys if key in known or not hosts[key][0]]
                for key in keys:
                    host, _, host_items = hosts[key]
                    if host and (len(authoritative) != 1 or key != authoritative[0]):
                        print_warning(
                            f"IP {ip} matches multiple hosts; exporting '{host}' by name."
                        )
                        hosts[key] = (host, "", host_items)
        for host, ip, host_items in sorted(
            hosts.values(), key=lambda item: (item[0].casefold(), item[1])
        ):
            host_items.sort(
                key=lambda item: (item["id"].casefold(), item["description"].casefold())
            )
            _append_item(root, host, ip, host_items)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(path, encoding="utf-8", xml_declaration=False)
