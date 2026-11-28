"""
Pre-Windows 2000 computer account assessment checks.

This module implements checks relating to pre-created Active Directory computer 
accounts susceptible to the legacy pre-Windows 2000 machine account password
convention.

Checks implemented within this module are intended to identify situations where 
Kerberos authentication can be achieved using predictable default machine 
account credentials.
"""

import os
import re
import stat
import struct
from pathlib import Path

from impacket.krb5.ccache import CCache
from pyasn1.error import PyAsn1Error

from ad_kit.core.checks import ANSI_ESCAPE_PATTERN, run_check
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import Finding
from ad_kit.core.findings import format_counted_commentary, load_finding


def pre2k_check(
    dc_ip: str,
    username: str,
    password: str,
) -> tuple[dict, list[Finding]]:
    """
    Identify pre-created computer accounts that permit authentication using the 
    legacy pre-Windows 2000 machine account password convention.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        A tuple containing:

        - Parsed pre-created computer account results.
        - Generated findings.
    """

    output = run_check(
        "pre2k",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "-M",
            "pre2k",
        ],
        kerberos_dc=dc_ip,
    )

    results = {
        "accounts_found": 0,
        "accounts": [],
        "tgt_obtained": False,
        "account_tgts": {},
    }

    findings: list[Finding] = []

    for line in output.splitlines():

        lower_line = line.lower()

        if "pre-created computer account:" in lower_line:

            account = (line.split(":")[-1].strip())
            results["accounts"].append(account)

        elif match := re.search(r"\bfound\s+(\d+)\s+pre-created computer accounts?\b", lower_line):

            results["accounts_found"] = int(match.group(1))

        elif "successfully obtained tgt" in lower_line:

            results["tgt_obtained"] = True

        match = re.search(
            r"\b(successfully obtained tgt|failed to get tgt|error obtaining tgt)"
            r"\s+for\s+([^\s@:]+)@",
            lower_line,
        )
        if match:
            account = match.group(2).removesuffix("$")
            results["account_tgts"][account] = {
                "successfully obtained tgt": "Successful",
                "failed to get tgt": "Failed",
                "error obtaining tgt": "Error",
            }[match.group(1)]

    if (
        results["accounts_found"] > 0
        and results["tgt_obtained"]
    ):

        finding = load_finding("pre2k", "PRE2K-001")
        format_counted_commentary(finding, results["accounts_found"], "account", "accounts")

        if len(results["accounts"]) == 1:

            finding.evidence.append(
                f"Pre-created computer account '{results['accounts'][0]}' was "
                "identified."
            )

        elif len(results["accounts"]) > 1:

            finding.evidence.append(
                "Multiple pre-created computer accounts were identified."
            )

        finding.evidence.append(
            "A Kerberos TGT was successfully "
            "obtained using the default machine account password convention."
        )

        findings.append(finding)

    return results, findings


def pre2k_cache_dir() -> Path:
    nxc_path = os.environ.get("NXC_PATH", str(Path.home() / ".nxc"))
    return Path(os.path.normpath(nxc_path)) / "modules" / "pre2k" / "ccache"


def _cache_signature(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def snapshot_pre2k_caches(cache_dir: Path) -> dict[str, tuple[int, int, int, int]]:
    try:
        with os.scandir(cache_dir) as entries:
            return {
                entry.name: _cache_signature(Path(entry.path).lstat())
                for entry in entries
                if entry.name.endswith(".ccache") and entry.is_file(follow_symlinks=False)
            }
    except FileNotFoundError:
        return {}


def validate_pre2k_ldap(
    account: str,
    domain: str,
    dc_ip: str,
    cache_dir: Path,
    before: dict[str, tuple[int, int, int, int]],
) -> tuple[bool, str]:
    """Use only a newly written, matching NetExec TGT cache for an LDAP bind."""
    principal = account.removesuffix("$").lower()
    if not account.endswith("$") or not re.fullmatch(r"[a-z0-9_.-]+", principal):
        return False, "Cannot safely determine the NetExec ticket cache filename."
    cache_path = cache_dir / f"{principal}.ccache"
    try:
        info = cache_path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return False, "The NetExec ticket cache is not a regular file."
        if before.get(cache_path.name) == _cache_signature(info):
            return False, "The NetExec ticket cache was not updated by this run."
        cache = CCache.loadFile(str(cache_path))
        if cache is None:
            return False, "The NetExec ticket cache could not be loaded."
        expected = f"{principal}@{domain}".casefold()
        client = cache.principal.prettyPrint().decode("utf-8").casefold()
        tgt_name = f"krbtgt/{domain}@{domain}".casefold()
        credential = cache.getCredential(tgt_name, anySPN=False)
        if credential is None:
            return False, "The NetExec cache contains no matching TGT."
        ticket_client = credential["client"].prettyPrint().decode("utf-8").casefold()
        ticket_server = credential["server"].prettyPrint().decode("utf-8").casefold()
        if (
            client.replace("$@", "@") != expected
            or ticket_client.replace("$@", "@") != expected
            or ticket_server != tgt_name
        ):
            return False, "The NetExec ticket cache does not match the account and domain."
    except FileNotFoundError:
        return False, "NetExec did not save a ticket cache for this account."
    except (
        OSError, ValueError, UnicodeError, KeyError, TypeError, IndexError,
        NotImplementedError, struct.error, PyAsn1Error,
    ):
        return False, "The NetExec ticket cache could not be read or verified."

    try:
        output = run_check(
            f"pre2k-ldap-{principal}",
            [
                "env", f"KRB5CCNAME={cache_path}", "nxc", "ldap", dc_ip,
                "--use-kcache", "--kdcHost", dc_ip, "--dns-server", dc_ip,
            ],
            show_progress=False, kerberos_dc=dc_ip,
        )
    except CheckExecutionError as exc:
        return False, str(exc)
    auth = re.compile(
        r"^\s*LDAPS?\s+\S+\s+\d+\s+\S+\s+\[\+\]\s+"
        + re.escape(domain) + r"\\" + re.escape(principal)
        + r"\$?\s+from ccache\b",
        re.IGNORECASE | re.MULTILINE,
    )
    if not auth.search(ANSI_ESCAPE_PATTERN.sub("", output)):
        return False, "NetExec did not confirm LDAP authentication using the matching cache."
    return True, ""