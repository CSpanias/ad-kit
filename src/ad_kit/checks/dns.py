"""
DNS-related assessment checks.

This module implements checks relating to Active Directory-integrated DNS 
(ADIDNS) permissions.

Checks implemented within this module are intended to identify situations where 
authenticated users are permitted to create DNS records within ADIDNS zones.
"""

import secrets

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


def dns_record_creation_check(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Check whether authenticated users can create DNS records within ADIDNS 
    zones.

    A temporary DNS record is created and removed to verify whether standard 
    domain users possess sufficient permissions to modify DNS data.

    Args:
        dc_ip:
            Domain Controller IP address.

        domain:
            Active Directory domain name.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing:

        - Parsed DNS permission results for display.
        - Generated findings.
    """

    findings: list[Finding] = []

    record_name = f"ad-kit-{secrets.token_hex(4)}"
    record_ip = "192.0.2.1"

    results = {
        "dns_record_creation": False,
        "record_name": f"{record_name}.{domain}",
        "record_ip": record_ip,

        "record_deleted": False,
        "cleanup_method": "None",
    }

    output = run_check(
        "dns-record-create",
        [
            "bloodyAD",
            "-u", username,
            "-p", password,
            "-d", domain,
            "--dc-ip", dc_ip,
            "add",
            "dnsRecord",
            record_name,
            record_ip,
        ],
    )

    if "successfully added" in output.lower():

        results["dns_record_creation"] = True

        finding = load_finding("dns_records", "DNS-001")

        finding.evidence.append(
            f"Authenticated user '{username}' successfully created DNS record "
            f"'{record_name}.{domain}'."
        )

        finding.evidence.append(
            f"The created DNS record resolved to {record_ip}."
        )

        findings.append(finding)

        remove_output = run_check(
            "dns-record-remove",
            [
                "bloodyAD",
                "-u", username,
                "-p", password,
                "-d", domain,
                "--dc-ip", dc_ip,
                "remove",
                "dnsRecord",
                record_name,
                record_ip,
            ],
        )

        if "successfully removed" in remove_output.lower():

            results["record_deleted"] = True
            results["cleanup_method"] = "Standard User"

            finding.evidence.append(
                "The temporary DNS record was successfully removed following "
                "testing."
            )

        if results["dns_record_creation"] and not results["record_deleted"]:

            finding.evidence.append(
                "The temporary DNS record could not be removed using the " \
                "standard user account."
            )

            results["cleanup_method"] = "Domain Admin Required"

    return results, findings