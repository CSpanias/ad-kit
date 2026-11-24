"""
DNS-related assessment checks.

This module implements checks relating to Active Directory-integrated DNS 
(ADIDNS) permissions.

Checks implemented within this module are intended to identify situations where 
authenticated users are permitted to create DNS records within ADIDNS zones.
"""

import re
import secrets

from ad_kit.core.checks import run_check, warn_test_artifact_remaining
from ad_kit.core.exceptions import ADKitError, CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding
from ad_kit.reporting.results import record_incomplete


def dns_confirmation_excerpt(output: str, record_name: str, record_ip: str) -> tuple[str, bool]:
    """Extract the exact record and verify its A value in bloodyAD's DNS dump."""
    matching = []
    confirmed = False
    for block in re.split(r"\n[ \t]*\n", output.strip()):
        name = re.search(r"(?im)^[ \t]*recordName:[ \t]*(\S+)[ \t]*$", block)
        if not name or name.group(1).rstrip(".").casefold() != record_name.rstrip(".").casefold():
            continue
        matching.append(block)
        addresses = re.findall(r"(?im)^[ \t]*A:[ \t]*(.*)$", block)
        if any(record_ip == address.strip() for line in addresses for address in line.split(";")):
            confirmed = True
    return "\n\n".join(matching), confirmed


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
        finding.evidence_in_commentary = True

        finding.evidence.append(
            f"Authenticated user '`{username}`' successfully created DNS "
            f"record '`{record_name}.{domain}`'."
        )

        findings.append(finding)

        try:
            try:
                confirmation = run_check(
                    "dns-record-confirm",
                    [
                        "bloodyAD", "-u", username, "-p", password, "-d", domain,
                        "--dc-ip", dc_ip, "get", "dnsDump",
                    ],
                )
            except CheckExecutionError as exc:
                record_incomplete("DNS record confirmation", results["record_name"], str(exc))
            else:
                _, confirmed = dns_confirmation_excerpt(
                    confirmation, results["record_name"], record_ip
                )
                if confirmed:
                    finding.evidence.append(
                        f"The DNS dump confirmed an A record for `{results['record_name']}` "
                        f"with address `{record_ip}`."
                    )
                else:
                    record_incomplete(
                        "DNS record confirmation", results["record_name"],
                        "The expected A record was not confirmed; see dns-record-confirm.txt.",
                    )
        finally:
            try:
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
            except (ADKitError, KeyboardInterrupt):
                warn_test_artifact_remaining(
                    "DNS record", results["record_name"], "dns-record-create"
                )
                raise

            if "successfully removed" in remove_output.lower():
                results["record_deleted"] = True
                results["cleanup_method"] = "Standard User"
                finding.evidence.append(
                    "The temporary DNS record was successfully removed following testing."
                )
            else:
                warn_test_artifact_remaining(
                    "DNS record", results["record_name"], "dns-record-create"
                )
                finding.evidence.append(
                    "The temporary DNS record could not be removed using the standard user account."
                )
                results["cleanup_method"] = "Domain Admin Required"

    return results, findings