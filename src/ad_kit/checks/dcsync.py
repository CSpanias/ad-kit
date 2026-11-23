"""
Checks for unexpected Active Directory replication rights.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import parse_domain_sid, run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding

ACE_BLOCK_PATTERN = re.compile(
    r"ACE\[\s*\d+\s*\]\s+info(.*?)(?=ACE\[\s*\d+\s*\]\s+info|\Z)",
    re.IGNORECASE | re.DOTALL,
)
ACE_TYPE_PATTERN = re.compile(r"ACE Type\s*:\s*(\S+)", re.IGNORECASE)
OBJECT_GUID_PATTERN = re.compile(
    r"Object type\s*\(GUID\)\s*:\s*.*?\(([0-9a-f-]{36})\)",
    re.IGNORECASE,
)
TRUSTEE_PATTERN = re.compile(
    r"Trustee\s*\(SID\)\s*:\s*(.+?)\s+\((S-\d+(?:-\d+)+)\)",
    re.IGNORECASE,
)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

DCSYNC_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": (
        "DS-Replication-Get-Changes-In-Filtered-Set"
    ),
}
REQUIRED_DCSYNC_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
}


class DCSyncTrustee(TypedDict):
    name: str
    sid: str
    rights: list[str]
    complete: bool


class _ParsedTrustee(TypedDict):
    name: str
    sid: str
    rights: set[str]


def _normalize_principal(name: str) -> str:
    return (
        name.strip()
        .rsplit("\\", 1)[-1]
        .rstrip("$")
        .casefold()
    )


def is_msol_trustee(trustee: DCSyncTrustee) -> bool:
    return _normalize_principal(trustee["name"]).startswith("msol_")


def _parse_dcsync_aces(output: str) -> list[DCSyncTrustee]:
    output = ANSI_ESCAPE_PATTERN.sub("", output)
    trustees: dict[str, _ParsedTrustee] = {}

    for match in ACE_BLOCK_PATTERN.finditer(output):
        block = match.group(1)
        ace_type_match = ACE_TYPE_PATTERN.search(block)

        if (
            ace_type_match is not None
            and not ace_type_match.group(1).upper().startswith("ACCESS_ALLOWED")
        ):
            continue

        guid_match = OBJECT_GUID_PATTERN.search(block)

        if guid_match is None:
            continue

        guid = guid_match.group(1).lower()

        if guid not in DCSYNC_RIGHTS:
            continue

        trustee_match = TRUSTEE_PATTERN.search(block)

        if trustee_match is None:
            raise RuntimeError(
                f"Could not parse the trustee for DCSync right {guid}."
            )

        name = trustee_match.group(1).strip()
        sid = trustee_match.group(2)
        key = sid.casefold()

        if key not in trustees:
            trustees[key] = {
                "name": name,
                "sid": sid,
                "rights": set(),
            }

        trustees[key]["rights"].add(guid)

    results: list[DCSyncTrustee] = []

    for trustee in trustees.values():
        rights = trustee["rights"]
        results.append(
            {
                "name": trustee["name"],
                "sid": trustee["sid"],
                "rights": sorted(DCSYNC_RIGHTS[guid] for guid in rights),
                "complete": REQUIRED_DCSYNC_RIGHTS.issubset(rights),
            }
        )

    return sorted(results, key=lambda trustee: trustee["name"].casefold())


def _default_trustee_sids(domain_sid: str) -> set[str]:
    return {
        f"{domain_sid}-512",
        f"{domain_sid}-516",
        f"{domain_sid}-519",
        f"{domain_sid}-521",
        f"{domain_sid}-498",
        "S-1-5-9",
        "S-1-5-18",
        "S-1-5-32-544",
    }


def dcsync_check(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    administrative_accounts: set[str],
    dc_hostnames: list[str],
) -> list[DCSyncTrustee]:
    """
    Identify non-default trustees assigned DCSync-related replication rights.

    Domain Admins, Enterprise Admins, Domain Controllers, Enterprise Domain
    Controllers, other well-known default administrators, and known members of
    the Domain Admins and Enterprise Admins groups are excluded.
    """

    sid_output = run_check(
        "dcsync-domain-sid",
        [
            "nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
            "--get-sid",
        ],
        sensitive_values=[password],
    )
    domain_sid = parse_domain_sid(sid_output)
    target_credential = f"{domain}/{username}:{password}"
    dacl_output = run_check(
        "dcsync-rights",
        [
            "dacledit.py",
            "-action", "read",
            "-rights", "DCSync",
            "-ace-type", "allowed",
            "-target-sid", domain_sid,
            "-dc-ip", dc_ip,
            target_credential,
        ],
        sensitive_values=[password, target_credential],
    )

    default_sids = {
        sid.casefold()
        for sid in _default_trustee_sids(domain_sid)
    }
    default_names = {
        "domain admins",
        "enterprise admins",
        "domain controllers",
        "enterprise domain controllers",
        "enterprise read-only domain controllers",
        "domain read-only controllers",
        "administrators",
        "system",
        *(_normalize_principal(name) for name in administrative_accounts),
        *(
            _normalize_principal(hostname.split(".", 1)[0])
            for hostname in dc_hostnames
        ),
    }
    trustees = [
        trustee
        for trustee in _parse_dcsync_aces(dacl_output)
        if trustee["sid"].casefold() not in default_sids
        and _normalize_principal(trustee["name"]) not in default_names
    ]

    return trustees


def dcsync_findings(trustees: list[DCSyncTrustee]) -> list[Finding]:
    findings: list[Finding] = []
    if trustees:
        finding = load_finding("privileged_excessive", "PRIV-005")

        for trustee in trustees:
            completeness = (
                "the complete core DCSync right set"
                if trustee["complete"]
                else "DCSync-related rights, but not the complete core set"
            )
            finding.evidence.append(
                f"{trustee['name']} ({trustee['sid']}) has "
                f"{', '.join(trustee['rights'])}; this is {completeness}."
            )

        findings.append(finding)

    return findings
