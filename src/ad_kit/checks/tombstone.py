"""
Checks for Standard User access to deleted Active Directory objects.
"""

import re
from typing import TypedDict

from ad_kit.core.checks import run_check


class TombstoneResult(TypedDict):
    dc_hostname: str
    deleted_objects: int | None
    sam_account_names: list[str]
    status: str


def tombstone_check(
    dc_ip: str,
    username: str,
    password: str,
) -> TombstoneResult:
    """
    Query deleted objects on a Domain Controller without modifying them.
    """

    output = run_check(
        f"tombstone-{dc_ip.replace(':', '-')}",
        [
            "nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
            "-M", "tombstone",
            "-o", "ACTION=query",
        ],
        sensitive_values=[password],
    )

    lower_output = output.lower()
    hostname_match = re.search(r"\(name:([^)]+)\)", output, re.IGNORECASE)
    dc_hostname = hostname_match.group(1).strip() if hostname_match else dc_ip
    sam_account_names = [
        value.strip()
        for value in re.findall(
            r"\bsAMAccountName[ \t]*:[ \t]*([^\r\n]*)",
            output,
            re.IGNORECASE,
        )
        if value.strip()
    ]

    if "could not find the deleted objects container" in lower_output:
        deleted_objects = None
        status = "Container not found"
    elif "no objects are in a tombstone state" in lower_output:
        deleted_objects = 0
        status = "No deleted objects"
    else:
        access_denied = any(
            marker in lower_output
            for marker in (
                "insufficientaccessrights",
                "insufficient access rights",
                "access_denied",
                "access denied",
                "permission denied",
            )
        )
        count_match = re.search(
            r"Found\s+(\d+)\s+deleted objects",
            output,
            re.IGNORECASE,
        )
        detail_count = len(
            re.findall(
                r"isDeleted\s*:\s*TRUE",
                output,
                re.IGNORECASE,
            )
        )
        deleted_objects = max(
            int(count_match.group(1)) if count_match else 0,
            detail_count,
            len(sam_account_names),
        )
        if deleted_objects:
            status = "Enumerated"
        elif access_denied:
            status = "Access denied"
            deleted_objects = None
        elif "error" in lower_output or "failed" in lower_output:
            status = "Unknown"
            deleted_objects = None
        elif count_match:
            status = "No deleted objects"
        else:
            status = "Unknown"
            deleted_objects = None

    return {
        "dc_hostname": dc_hostname,
        "deleted_objects": deleted_objects,
        "sam_account_names": sam_account_names,
        "status": status,
    }
