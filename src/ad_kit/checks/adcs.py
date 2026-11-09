"""
Active Directory Certificate Services (AD CS) assessment checks.

This module implements checks relating to ADCS misconfigurations.

Checks implemented within this module are intended to identify certificate 
templates and Certification Authorities vulnerable to known ESC attack paths.
"""


from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding


SUPPORTED_ESC_FINDINGS = {
    "ESC1": "ADCS-ESC1",
    "ESC8": "ADCS-ESC8",
    "ESC15": "ADCS-ESC15",
}

SUPPORTED_ESC_CLASSES = (
    "ESC1",
    "ESC2",
    "ESC3",
    "ESC4",
    "ESC6",
    "ESC8",
    "ESC9",
    "ESC10",
    "ESC13",
    "ESC15",
    "ESC16",
)


def adcs_check(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Assess Active Directory Certificate Services (AD CS) configurations.

    Args:
        dc_ip:
            Domain Controller IP address.

        domain:
            Active Directory domain.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing:

        - Parsed AD CS results.
        - Generated findings.
    """

    results = {
        esc: []
        for esc in SUPPORTED_ESC_CLASSES
    }

    findings: list[Finding] = []

    output = run_check(
        "adcs-find",
        [
            "certipy",
            "find",
            "-u",
            f"{username}@{domain}",
            "-p",
            password,
            "-dc-ip",
            dc_ip,
            "-stdout",
            "-vuln",
        ],
    )

    current_template = None
    current_ca = None

    for line in output.splitlines():

        line = line.strip()

        # Template names
        if line.startswith("Template Name"):

            try:
                current_template = line.split(":", 1)[1].strip()

            except IndexError:
                continue

        # Certificate Authorities
        elif line.startswith("CA Name"):

            try:
                current_ca = line.split(":", 1)[1].strip()

            except IndexError:
                continue

        # ESC Vulnerabilities
        for esc in SUPPORTED_ESC_CLASSES:

            if esc not in line:
                continue

            if esc == "ESC8":
                if current_ca:
                    results[esc].append(current_ca)

            else:
                if current_template:
                    results[esc].append(current_template)

            break

    # Generate findings
    for esc, finding_id in SUPPORTED_ESC_FINDINGS.items():

        if not results[esc]:
            continue

        finding = load_finding("adcs", finding_id)

        for asset in sorted(set(results[esc])):

            if esc == "ESC8":

                finding.evidence.append(
                    f"Certification Authority '{asset}' was identified as "
                    f"vulnerable to {esc}."
                )

            else:

                finding.evidence.append(
                    f"Certificate template '{asset}' was identified as "
                    f"vulnerable to {esc}."
                )

        findings.append(finding)

    return results, findings