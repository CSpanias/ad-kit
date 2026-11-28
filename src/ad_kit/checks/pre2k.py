"""
Pre-Windows 2000 computer account assessment checks.

This module implements checks relating to pre-created Active Directory computer 
accounts susceptible to the legacy pre-Windows 2000 machine account password
convention.

Checks implemented within this module are intended to identify situations where 
Kerberos authentication can be achieved using predictable default machine 
account credentials.
"""

import re
import struct

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP
from impacket.krb5.kerberosv5 import KerberosError, SessionKeyDecryptionError, getKerberosTGT
from impacket.krb5.types import KerberosException, Principal
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError
from pyasn1.codec.der import decoder
from pyasn1.error import PyAsn1Error

from ad_kit.core.checks import run_check
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


def validate_pre2k_ldap(
    account: str, domain: str, dc_ip: str, dc_hostname: str
) -> tuple[bool, list[str], str]:
    """Request a TGT and use that same ticket to authenticate to LDAP."""
    principal = account.removesuffix("$").lower()
    password = principal[:14]
    lines = [
        f"[*] Requesting a TGT for {principal}@{domain} (Impacket, in-process).",
    ]
    try:
        tgt, cipher, _old_key, session_key = getKerberosTGT(
            Principal(principal, type=constants.PrincipalNameType.NT_PRINCIPAL.value),
            password, domain, "", "", kdcHost=dc_ip,
        )
        response, trailing = decoder.decode(tgt, asn1Spec=AS_REP())
        ticket_principal = Principal().from_asn1(response, "crealm", "cname")
        if (
            trailing
            or len(ticket_principal.components) != 1
            or ticket_principal.components[0].casefold().removesuffix("$") != principal.casefold()
            or ticket_principal.realm.casefold() != domain.casefold()
        ):
            reason = "The TGT client principal did not match the selected account and domain."
            lines.append(f"[-] {reason}")
            return False, lines, reason
        lines.append(f"[+] TGT obtained for {principal}@{domain}.")
        lines.append(f"[*] Authenticating to LDAP on {dc_hostname} using that TGT.")
        connection = LDAPConnection(f"ldap://{dc_hostname}", dstIp=dc_ip)
        try:
            authenticated = connection.kerberosLogin(
                ticket_principal.components[0], "", domain=domain, kdcHost=dc_ip,
                TGT={"KDC_REP": tgt, "cipher": cipher, "sessionKey": session_key},
                useCache=False,
            )
        finally:
            connection.close()
        if not authenticated:
            reason = "LDAP authentication was not confirmed."
            lines.append(f"[-] {reason}")
            return False, lines, reason
    except (PyAsn1Error, struct.error) as exc:
        reason = f"{type(exc).__name__}: Invalid Kerberos or LDAP response."
        lines.append(f"[-] Validation failed: {reason}")
        return False, lines, reason
    except (
        KerberosError, KerberosException, SessionKeyDecryptionError,
        LDAPSessionError, OSError,
    ) as exc:
        reason = f"{type(exc).__name__}: {exc}".replace(password, "[REDACTED]")
        lines.append(f"[-] Validation failed: {reason}")
        return False, lines, reason

    lines.append(f"[+] LDAP authentication succeeded for {account} using the TGT.")
    return True, lines, ""