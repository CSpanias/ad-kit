"""
NoPAC vulnerability assessment.
"""

import re
from typing import Literal, TypedDict

from ad_kit.core.checks import run_check
from ad_kit.core.finding import Finding
from ad_kit.core.findings import load_finding

PAC_TGT_SIZE_PATTERN = re.compile(r"TGT with PAC size\s+(\d+)", re.IGNORECASE)
NO_PAC_TGT_SIZE_PATTERN = re.compile(
    r"TGT without PAC size\s+(\d+)",
    re.IGNORECASE,
)


class NoPACResult(TypedDict):
    dc_ip: str
    with_pac_size: int | None
    without_pac_size: int | None
    status: Literal["Vulnerable", "Not vulnerable", "Unable to assess"]


def _tgt_size(pattern: re.Pattern[str], output: str) -> int | None:
    match = pattern.search(output)
    return int(match.group(1)) if match is not None else None


def _parse_result(dc_ip: str, output: str) -> NoPACResult:
    with_pac_size = _tgt_size(PAC_TGT_SIZE_PATTERN, output)
    without_pac_size = _tgt_size(NO_PAC_TGT_SIZE_PATTERN, output)

    if "VULNERABLE" in output.upper() or (
        with_pac_size is not None
        and without_pac_size is not None
        and without_pac_size < with_pac_size
    ):
        status: Literal["Vulnerable", "Not vulnerable", "Unable to assess"] = (
            "Vulnerable"
        )
    elif with_pac_size is not None and without_pac_size is not None:
        status = "Not vulnerable"
    else:
        status = "Unable to assess"

    return {
        "dc_ip": dc_ip,
        "with_pac_size": with_pac_size,
        "without_pac_size": without_pac_size,
        "status": status,
    }


def nopac_check(
    dc_ips: list[str],
    username: str,
    password: str,
) -> tuple[list[NoPACResult], list[Finding]]:
    """
    Compare PAC and non-PAC TGT responses from each discovered Domain Controller.

    The NetExec module requests Kerberos tickets but does not modify directory
    objects or account passwords.
    """

    results: list[NoPACResult] = []

    for dc_ip in dc_ips:
        output = run_check(
            f"nopac-{dc_ip.replace(':', '-')}",
            [
                "nxc", "smb", dc_ip,
                "-u", username,
                "-p", password,
                "-M", "nopac",
            ],
            sensitive_values=[password],
        )
        results.append(_parse_result(dc_ip, output))

    vulnerable_results = [
        result
        for result in results
        if result["status"] == "Vulnerable"
    ]
    findings: list[Finding] = []

    if vulnerable_results:
        finding = load_finding("nopac", "NOPAC-001")
        for result in vulnerable_results:
            finding.affected_assets.append(result["dc_ip"])
            finding.evidence.append(
                f"{result['dc_ip']} returned a TGT of "
                f"{result['with_pac_size']} bytes with a PAC and "
                f"{result['without_pac_size']} bytes without a PAC."
            )
        findings.append(finding)

    return results, findings
