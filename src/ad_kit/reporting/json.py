"""
JSON findings export.

Exports assessment findings in a machine-readable format suitable for
integration with external reporting platforms, using the same shape as the
other audit tools:

    {"findings": [{"id": ..., "description": ...}, ...]}
"""

import json
from pathlib import Path

from ad_kit.core.finding import Finding


GENERIC_FINDINGS: dict[str, dict[str, str]] = {
    # SMB
    "SMB-001": {
        "generic_id": "smb-signing-not-enforced",
        "description": "SMB signing was not enforced on one or more hosts."
    },
    "SMB-002": {
        "generic_id": "smbv1-enabled",
        "description": "The legacy SMBv1 protocol was enabled on one or more hosts.",
    },
    "SMB-003": {
        "generic_id": "smb-null-sessions",
        "description": "Anonymous SMB sessions could enumerate shares and account information.",
    },
    "SMB-004": {
        "generic_id": "weak-smb-share-permissions",
        "description": "The Standard User had write access to one or more SMB shares.",
    },
    # LDAP
    "LDAP-001": {
        "generic_id": "ldap-signing-not-enforced",
        "description": "LDAP signing was not enforced on one or more Domain Controllers.",
    },
    "LDAP-002": {
        "generic_id": "ldap-channel-binding-not-enforced",
        "description": "LDAP channel binding was not enforced on one or more Domain Controllers.",
    },
    "LDAP-003": {
        "generic_id": "ldap-null-binds",
        "description": "Anonymous LDAP binds were permitted on one or more Domain Controllers, allowing unauthenticated directory queries.",
    },
    # DNS
    "DNS-001": {
        "generic_id": "dns-record-creation",
        "description": "The Standard User could create and modify DNS records within Active Directory-integrated DNS zones.",
    },
    # Machine Account Quota
    "MAQ-001": {
        "generic_id": "maq-set-to-10",
        "description": "The Machine Account Quota was set to the default value of 10, allowing machine account creation.",
    },
    # Authentication coercion
    "COERCE-001": {
        "generic_id": "dc-coercion",
        "description": "Domain Controllers were susceptible to authentication coercion techniques such as PrinterBug and PetitPotam.",
    },
    # Password policy
    "PASS-001": {
        "generic_id": "weak-password-policy",
        "description": "The domain password or account lockout policy was below the recommended baseline.",
    },
    "PASS-002": {
        "generic_id": "password-not-required",
        "description": "Enabled user accounts exist with the PASSWD_NOTREQD flag set.",
    },
    # AS-REP roasting
    "ASREP-001": {
        "generic_id": "as-rep-roasting",
        "description": "Accounts configured without Kerberos pre-authentication are susceptible to AS-REP roasting.",
    },
    "ASREP-002": {
        "generic_id": "as-rep-roasting",
        "description": "Privileged accounts configured without Kerberos pre-authentication were susceptible to AS-REP roasting.",
    },
    # Kerberoasting
    "KERB-001": {
        "generic_id": "kerberoasting",
        "description": "Accounts with Service Principal Names could be targeted through Kerberoasting.",
    },
    "KERB-002": {
        "generic_id": "kerberoasting",
        "description": "Privileged accounts have Service Principal Names and could be targeted through Kerberoasting.",
    },
    # AD CS
    "ADCS-ESC1": {
        "generic_id": "ad-cs-esc1",
        "description": "A certificate template was vulnerable to ESC1, allowing certificate-based impersonation.",
    },
    "ADCS-ESC8": {
        "generic_id": "ad-cs-esc8",
        "description": "AD CS web enrolment was vulnerable to NTLM relay (ESC8).",
    },
    "ADCS-ESC15": {
        "generic_id": "ad-cs-esc15",
        "description": "A certificate template was vulnerable to ESC15 (CVE-2024-49019).",
    },
    # NoPAC
    "NOPAC-001": {
        "generic_id": "nopac",
        "description": "Domain Controllers were vulnerable to the NoPAC vulnerability.",
    },
    # Pre-Windows 2000
    "PRE2K-001": {
        "generic_id": "pre2k",
        "description": "Pre-created computer accounts permitted authentication using predictable credentials.",
    },
    # Delegation
    "DELEG-001": {
        "generic_id": "unconstrained-delegation",
        "description": "Accounts were configured with unconstrained delegation.",
    },
}

_generic_findings: list[dict] = []


def collect(findings: list[Finding]) -> None:
    """
    Collect generic findings from ad-kit findings.

    Only findings with an entry in ``GENERIC_FINDINGS`` are collected so that
    unmapped findings do not reach the adapter.
    """

    for finding in findings:
        generic = GENERIC_FINDINGS.get(finding.id)
        if generic:
            _generic_findings.append(
                {
                    "id": generic["generic_id"],
                    "description": generic["description"],
                }
            )


def reset() -> None:
    """Clear collected findings before starting a new run."""

    _generic_findings.clear()


def write_findings(path: str | Path) -> None:
    """Write the collected findings to a JSON file."""

    findings = sorted(
        _generic_findings,
        key=lambda item: (item["id"].casefold(), item["description"].casefold()),
    )

    output = {"findings": findings}

    Path(path).write_text(
        json.dumps(output, indent=4) + "\n",
        encoding="utf-8",
    )