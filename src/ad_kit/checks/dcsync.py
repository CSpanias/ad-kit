"""
Checks for unexpected Active Directory replication rights.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import parse_domain_sid, run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import (
    format_counted_commentary,
    load_finding,
    load_finding_definition,
)
from ad_kit.core.util import count_form

ACE_BLOCK_PATTERN = re.compile(
    r"ACE\[\s*\d+\s*\]\s+info(.*?)(?=ACE\[\s*\d+\s*\]\s+info|\Z)",
    re.IGNORECASE | re.DOTALL,
)
ACE_TYPE_PATTERN = re.compile(r"ACE Type\s*:\s*(\S+)", re.IGNORECASE)
ACE_FLAGS_PATTERN = re.compile(r"ACE flags\s*:\s*([^\r\n]*)", re.IGNORECASE)
OBJECT_FLAGS_PATTERN = re.compile(
    r"(?m)^[ \t]*(?:\[\*\][ \t]*)?Flags[ \t]*:[ \t]*([^\r\n]*)", re.IGNORECASE
)
OBJECT_TYPE_FIELD_PATTERN = re.compile(r"Object type\s*\(GUID\)\s*:", re.IGNORECASE)
ACCESS_MASK_PATTERN = re.compile(
    r"Access mask\s*:\s*[^\r\n]*\((0x[0-9a-f]+)\)", re.IGNORECASE
)
OBJECT_GUID_PATTERN = re.compile(
    r"Object type\s*\(GUID\)\s*:\s*.*?\(([0-9a-f-]{36})\)",
    re.IGNORECASE,
)
TRUSTEE_PATTERN = re.compile(
    r"Trustee\s*\(SID\)\s*:\s*(.+?)\s+\((S-\d+(?:-\d+)+)\)",
    re.IGNORECASE,
)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
GENERIC_ALL = 0x10000000
FULL_CONTROL = 0x000F01FF
CONTROL_ACCESS = 0x00000100

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
    generic_all: bool


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

        if ace_type_match is not None and not ace_type_match.group(1).upper().startswith(
            "ACCESS_ALLOWED"
        ):
            continue

        ace_flags = ACE_FLAGS_PATTERN.search(block)
        if ace_flags and "INHERIT_ONLY_ACE" in ace_flags.group(1).upper():
            continue

        guid_match = OBJECT_GUID_PATTERN.search(block)
        guid = guid_match.group(1).lower() if guid_match else None
        mask_match = ACCESS_MASK_PATTERN.search(block)
        if mask_match is None:
            if guid in DCSYNC_RIGHTS or (
                ace_type_match is not None
                and ace_type_match.group(1).upper()
                in {"ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"}
            ):
                raise RuntimeError("Could not parse an allowed ACE's access mask.")
            continue
        mask = int(mask_match.group(1), 16)
        object_flags = OBJECT_FLAGS_PATTERN.search(block)
        has_object_type = bool(
            OBJECT_TYPE_FIELD_PATTERN.search(block)
            or object_flags and "ACE_OBJECT_TYPE_PRESENT" in object_flags.group(1).upper()
        )
        if has_object_type and guid is None and mask & (GENERIC_ALL | CONTROL_ACCESS):
            raise RuntimeError("Could not parse the object type for an access-control ACE.")

        generic_all = not has_object_type and (
            bool(mask & GENERIC_ALL) or (mask & FULL_CONTROL) == FULL_CONTROL
        )
        replication_right = (
            guid in DCSYNC_RIGHTS and bool(mask & (CONTROL_ACCESS | GENERIC_ALL))
        )
        if not generic_all and not replication_right:
            continue
        if ace_type_match is None:
            raise RuntimeError("Could not parse the ACE type for DCSync-related rights.")

        trustee_match = TRUSTEE_PATTERN.search(block)

        if trustee_match is None:
            raise RuntimeError(
                f"Could not parse the trustee for {guid or 'GenericAll'}."
            )

        name = trustee_match.group(1).strip()
        sid = trustee_match.group(2)
        key = sid.casefold()

        if key not in trustees:
            trustees[key] = {
                "name": name,
                "sid": sid,
                "rights": set(),
                "generic_all": False,
            }

        if replication_right and guid is not None:
            trustees[key]["rights"].add(guid)
        trustees[key]["generic_all"] |= generic_all

    results: list[DCSyncTrustee] = []

    for trustee in trustees.values():
        rights = trustee["rights"]
        results.append(
            {
                "name": trustee["name"],
                "sid": trustee["sid"],
                "rights": (
                    (["GenericAll"] if trustee["generic_all"] else [])
                    + sorted(DCSYNC_RIGHTS[guid] for guid in rights)
                ),
                "complete": trustee["generic_all"] or REQUIRED_DCSYNC_RIGHTS.issubset(rights),
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
    Identify non-default trustees assigned DCSync rights or domain GenericAll.

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
    complete_trustees = [trustee for trustee in trustees if trustee["complete"]]
    if complete_trustees:
        finding = load_finding("privileged_excessive", "PRIV-005")
        format_counted_commentary(finding, len(complete_trustees), "principal", "principals")
        trustee_form = count_form(len(complete_trustees), "principal was", "principals were")
        has_generic_all = any("GenericAll" in trustee["rights"] for trustee in complete_trustees)
        if has_generic_all:
            definition = load_finding_definition("privileged_excessive", "PRIV-005")
            finding.commentary = (
                finding.commentary.strip() + "\n\n" + definition["generic_all_commentary"].strip()
            )
            finding.remediation = (
                finding.remediation.strip() + "\n\n" + definition["generic_all_remediation"].strip()
            )
            finding.evidence_introduction = (
                f"The following {trustee_form} found to have GenericAll on the domain "
                "naming context or the complete core DCSync right set "
                "(DS-Replication-Get-Changes, DS-Replication-Get-Changes-All):"
            )
        else:
            finding.evidence_introduction = (
                f"The following {trustee_form} found to have the complete core DCSync right set "
                "(DS-Replication-Get-Changes, DS-Replication-Get-Changes-All):"
            )

        for trustee in complete_trustees:
            evidence = f"`{trustee['name']}` ({trustee['sid']})"
            if has_generic_all:
                labels = []
                if "GenericAll" in trustee["rights"]:
                    labels.append("GenericAll")
                if {DCSYNC_RIGHTS[guid] for guid in REQUIRED_DCSYNC_RIGHTS}.issubset(
                    trustee["rights"]
                ):
                    labels.append("explicit core DCSync rights")
                evidence += " - " + "; ".join(labels)
            finding.evidence.append(evidence)

        findings.append(finding)

    return findings
