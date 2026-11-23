import re

from rich.table import Table
from rich.text import Text

from ad_kit.checks.asreproast import (
    asreproast_check,
    asreproast_privileged_check,
)
from ad_kit.checks.ldap import ldap_check
from ad_kit.checks.smb import (
    ShareAccess,
    smb_configuration_check,
    smb_share_access_check,
)
from ad_kit.checks.tombstone import tombstone_check
from ad_kit.core.checks import (
    CheckEvidence,
    capture_check_evidence,
    format_check_evidence,
    load_dc_hostnames,
    load_domain_computers,
)
from ad_kit.core.console import console, print_info, print_section, print_warning
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.findings import load_finding
from ad_kit.core.util import (
    get_artefacts_dir,
    parallel_items,
    progress,
    require_collected_data,
    require_session,
    track_items,
    unique_hosts,
)
from ad_kit.reporting.results import record_findings, record_incomplete

from .credentials import authenticate_standard_user


def _enumeration_excerpt(output: str, kind: str) -> tuple[str, bool]:
    """Return a NetExec table with at most ten result rows."""
    header = None
    rows = []
    messages = []
    for line in output.splitlines():
        plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
        match = re.match(r"^\s*(?:SMB|LDAP|LDAPS)\s+\S+\s+\d+\s+\S+\s+(.*)$", plain, re.I)
        if not match:
            continue
        payload = match.group(1).strip()
        lower = payload.lower()
        if payload.startswith("[-]") or lower.startswith("enumerated "):
            messages.append(plain)
            if header:
                break
            continue
        is_header = (
            "username" in lower and "last pw set" in lower
            if kind == "users"
            else all(word in lower for word in ("share", "permissions", "remark"))
        )
        if is_header:
            header = plain
            continue
        if header:
            if kind == "shares" and "username" in lower and "last pw set" in lower:
                break
            if not payload or re.fullmatch(r"[-\s]+", payload):
                continue
            if payload.startswith(("[+]", "[*]", "[!]")):
                break
            rows.append(plain)
    if not rows:
        return "", False
    lines = messages + [header] + rows[:10]
    if len(rows) > 10:
        lines.append(f"... {len(rows) - 10} additional row(s) omitted.")
    return "\n".join(lines), True


def _show_anonymous_evidence(
    records: list[CheckEvidence], results: list[dict], protocol: str
) -> None:
    sample: tuple[str, tuple[str, str], list[CheckEvidence]] | None = None
    best_rank = 3
    for result in results:
        host = result["dc_hostname"] if protocol == "ldap" else result["host"]
        permitted = (
            result["anonymous_bind"] == "[red]✗ Permitted[/red]"
            if protocol == "ldap"
            else result["null_auth"] is True
        )
        if not permitted:
            continue
        names = (
            (f"ldap-{host}", f"ldap-anonymous-users-{host}")
            if protocol == "ldap"
            else (f"smb-{host}", f"smb-anonymous-enumeration-{host}")
        )
        selected = [record for record in records if record.name in names]
        if not selected:
            continue
        enumeration = next((record for record in selected if record.name == names[1]), None)
        rank = 2
        if enumeration:
            if _enumeration_excerpt(enumeration.stdout, "users")[1]:
                rank = 0
            elif protocol == "smb" and _enumeration_excerpt(enumeration.stdout, "shares")[1]:
                rank = 1
        if rank < best_rank:
            sample = (host, names, selected)
            best_rank = rank
            if rank == 0:
                break

    if sample is None:
        console.print()
        return
    host, names, selected = sample
    console.print(f"\nAnonymous evidence - {host}\n", markup=False)
    for record in selected:
        if record.name == names[0]:
            excerpt = record.stdout
        else:
            excerpt, found = _enumeration_excerpt(record.stdout, "users")
            if not found and protocol == "smb":
                excerpt, found = _enumeration_excerpt(record.stdout, "shares")
            if not found:
                lines = record.stdout.splitlines()
                excerpt = "\n".join(lines[:10])
                if len(lines) > 10:
                    excerpt += "\n... Additional output omitted."
                excerpt += "\nNo user or share rows confirmed in this output."
        console.print(
            format_check_evidence(record, excerpt), markup=False, highlight=False
        )
        console.print()


def run_ldap_checks() -> None:
    """
    Execute LDAP security checks against all discovered
    Domain Controllers.

    This check evaluates LDAP signing requirements,
    LDAP channel binding enforcement, and anonymous
    LDAP bind permissions. Results are displayed in
    tabular format and any findings are written to a
    dedicated Markdown report.

    Findings are aggregated across all discovered
    Domain Controllers to provide a domain-wide view
    of LDAP security configuration.
    """

    print_section("LDAP Checks")

    with capture_check_evidence() as evidence, progress("Checking LDAP configuration..."):

        ldap_results, ldap_findings = ldap_check()

    table = Table()

    table.add_column("DC", style="cyan")
    table.add_column("LDAP Signing", style="green")
    table.add_column("Channel Binding", style="green")
    table.add_column("Anonymous Bind", style="green")

    for result in ldap_results:

        table.add_row(
            result["dc_hostname"],
            result["signing"],
            result["channel_binding"],
            result["anonymous_bind"],
        )

    console.print(table)
    _show_anonymous_evidence(evidence, ldap_results, "ldap")

    record_findings(ldap_findings)

def run_tombstone_checks(
    std_pass: str | None = None,
) -> None:
    """
    Check whether the Standard User can query deleted AD objects.

    The check uses the tombstone module's query action only; it never restores
    or deletes objects.
    """

    session_data = require_session()
    standard_user = session_data.get("standard_user", "")
    if not standard_user:
        print_info(
            "Skipping deleted-object checks: no Standard User is configured "
            "for this session."
        )
        return

    if std_pass is None:
        std_pass = authenticate_standard_user()

    dc_ips = sorted(set(session_data.get("dc_ips") or [session_data["dc_ip"]]))
    results = []
    findings = []

    console.print()
    with progress("Checking Standard User access to deleted objects..."):

        for dc_ip in track_items(dc_ips, "Deleted-object domain controllers"):
            results.append(
                tombstone_check(
                    dc_ip,
                    standard_user,
                    std_pass,
                )
            )

    print_section("Deleted AD Object Access")

    table = Table()
    table.add_column("Domain Controller", style="cyan")
    table.add_column("Deleted Objects", style="yellow")
    table.add_column("Standard User Access", style="green")

    for result in results:
        deleted_objects = result["deleted_objects"]
        table.add_row(
            result["dc_hostname"],
            (
                str(deleted_objects)
                if deleted_objects is not None
                else "N/A"
            ),
            result["status"],
        )

    console.print(table)

    accessible_objects = [
        result
        for result in results
        if result["deleted_objects"] is not None
        and result["deleted_objects"] > 0
    ]

    if accessible_objects:
        finding = load_finding("tombstone", "TOMB-001")

        for result in accessible_objects:
            dc_hostname = result["dc_hostname"]
            deleted_objects = result["deleted_objects"]
            evidence = (
                f"Standard User '{standard_user}' enumerated "
                f"{deleted_objects} deleted object(s) on '{dc_hostname}'."
            )
            sam_account_names = result["sam_account_names"]
            if sam_account_names:
                evidence += (
                    " Their `sAMAccountName` values are the following:\n"
                    + "\n".join(
                        f"  - {name}"
                        for name in sam_account_names
                    )
                )
            finding.evidence.append(evidence)
            finding.affected_assets.append(dc_hostname)

        finding.affected_assets = sorted(set(finding.affected_assets))
        findings.append(finding)

    record_findings(findings)

def _null_session_status(null_auth: bool | None) -> str:
    if null_auth is True:
        return "[red]✗ Permitted[/red]"
    return "[yellow]⚠ Not confirmed[/yellow]"


def _anonymous_count(
    count: int | None, null_auth: bool | None, *, complete: bool = True
) -> str:
    if not complete and count is not None:
        return f"Incomplete ({count} observed)"
    if count is not None:
        return str(count)
    return "Not attempted" if null_auth is False else "Incomplete"


def _check_share_access(
    hosts: list[str], dc_ip: str, username: str, password: str
) -> list[tuple[str, list[ShareAccess], list[str]]]:
    targets = unique_hosts(hosts)
    checked = parallel_items(
        targets, "SMB share-access hosts",
        lambda host: smb_share_access_check(host, dc_ip, username, password),
    )
    return [(host, *result) for host, result in zip(targets, checked)]


def run_smb_checks(
    std_pass: str | None = None,
) -> str | None:
    """
    Execute SMB security checks against discovered hosts.

    This check evaluates SMB signing, SMBv1, anonymous enumeration, and
    Standard User read and write access to shares across discovered systems.

    Findings are intended to identify legacy SMB configurations and systems 
    vulnerable to common relay or downgrade attacks.

    Args:
        std_pass:
            Previously validated Standard User password, if already available.

    Returns:
        The password used for SMB checks, or None if authentication was not
        needed.
    """

    session_data = require_session()
    require_collected_data(
        session_data, "domain_computers_exported", "Domain computer"
    )

    smb_results = []
    findings = []

    smb_signing_disabled = []
    smbv1_enabled = []
    anonymous_enumeration = []

    unknown_hosts = []
    anonymous_failed_hosts = []

    hosts = load_domain_computers()
    dcs = {dc.rstrip(".").casefold() for dc in load_dc_hostnames()}

    def check_host(host: str) -> tuple[str, dict | None, str | None, list[CheckEvidence]]:
        with capture_check_evidence() as captured:
            try:
                result = smb_configuration_check(
                    host,
                    session_data["dc_ip"],
                    enumerate_users=host.rstrip(".").casefold() in dcs,
                )
            except CheckExecutionError as exc:
                return host, None, str(exc), captured
            return host, result, None, captured

    with capture_check_evidence() as evidence, progress("Checking SMB configuration..."):
        checked = parallel_items(
            unique_hosts(hosts), "SMB configuration hosts", check_host
        )
        for host, result, error, captured in checked:
            evidence.extend(captured)
            if error is not None:
                record_incomplete("SMB configuration", host, error, notify=False)
                unknown_hosts.append(host)
                continue
            if result is None:
                raise RuntimeError(f"No SMB configuration result for {host}")
            for reason in result["anonymous_incomplete"]:
                record_incomplete("SMB anonymous enumeration", host, reason, notify=False)

            unknown = [
                label
                for value, label in (
                    (result["signing"] == "[yellow]⚠ Unknown[/yellow]", "signing"),
                    (result["smbv1"] == "[yellow]⚠ Unknown[/yellow]", "SMBv1"),
                    (result["null_auth"] is None, "anonymous access"),
                )
                if value
            ]
            if unknown:
                unknown_hosts.append(result["host"])
                record_incomplete(
                    "SMB configuration", host, f"Unknown: {', '.join(unknown)}",
                    notify=False,
                )
            if len(unknown) == 3:
                continue
            is_dc = host.rstrip(".").casefold() in dcs
            if result["null_auth"] and (
                result["anonymous_shares"] is None
                or (
                    is_dc
                    and not result.get(
                        "anonymous_users_complete", result["anonymous_users"] is not None
                    )
                )
            ):
                anonymous_failed_hosts.append(result["host"])

            smb_results.append(result)

    dc_results = []
    host_results = []

    for result in smb_results:

        if result["signing"] == "[red]✗ Disabled[/red]":

            smb_signing_disabled.append(result["host"])

        if result["smbv1"] == "[red]✗ Enabled[/red]":

            smbv1_enabled.append(result["host"])

        if result["anonymous_shares"] or result["anonymous_users"]:
            anonymous_enumeration.append(result)

        host = result["host"].rstrip(".").casefold()

        if host in dcs:
            dc_results.append(result)
        else:
            host_results.append(result)

    print_section("SMB Checks - Domain Controllers")

    dc_table = Table()

    dc_table.add_column("Host", style="cyan")
    dc_table.add_column("Signing", style="green")
    dc_table.add_column("SMBv1", style="green")
    dc_table.add_column("Null Session", style="yellow")
    dc_table.add_column("Anon Shares (count)", style="yellow")
    dc_table.add_column("Anon Users (count)", style="yellow")

    for result in dc_results:

        dc_table.add_row(
            result["host"],
            result["signing"],
            result["smbv1"],
            _null_session_status(result["null_auth"]),
            _anonymous_count(result["anonymous_shares"], result["null_auth"]),
            _anonymous_count(
                result["anonymous_users"],
                result["null_auth"],
                complete=result.get("anonymous_users_complete", True),
            ),
        )

    console.print(dc_table)

    print_section("SMB Checks - Hosts")

    host_table = Table()

    host_table.add_column("Host", style="cyan")
    host_table.add_column("Signing", style="green")
    host_table.add_column("SMBv1", style="green")
    host_table.add_column("Null Session", style="yellow")
    host_table.add_column("Anon Shares (count)", style="yellow")

    for result in host_results:

        host_table.add_row(
            result["host"],
            result["signing"],
            result["smbv1"],
            _null_session_status(result["null_auth"]),
            _anonymous_count(result["anonymous_shares"], result["null_auth"]),
        )

    console.print(host_table)
    _show_anonymous_evidence(evidence, dc_results + host_results, "smb")

    share_access_results = []
    share_failed_hosts = []
    standard_user = session_data.get("standard_user", "")
    share_checks_run = False
    if hosts:
        if standard_user:
            if std_pass is None:
                try:
                    std_pass = authenticate_standard_user()
                except CheckExecutionError as exc:
                    record_incomplete("SMB share access", "all hosts", str(exc))
            if std_pass is not None:
                share_checks_run = True

            if share_checks_run:
                with progress("Checking SMB share access..."):

                    for host, shares, errors in _check_share_access(
                        hosts,
                        session_data["dc_ip"],
                        standard_user,
                        std_pass,
                    ):
                        if errors:
                            share_failed_hosts.append(host)
                            for error in errors:
                                record_incomplete("SMB share access", host, error, notify=False)

                        if shares:
                            share_access_results.append({
                                "host": host,
                                "shares": shares,
                            })
        else:
            record_incomplete(
                "SMB share access", "all hosts",
                "No Standard User is configured for this session",
            )

    print_section("SMB Checks - Share Access")

    share_table = Table()
    share_table.add_column("Host", style="cyan")
    share_table.add_column("Share", style="yellow")
    share_table.add_column("Permissions", style="yellow")

    for result in share_access_results:

        for share in result["shares"]:
            share_table.add_row(
                result["host"], Text(share["name"]), ", ".join(share["permissions"])
            )

    console.print(share_table)

    if share_checks_run and not share_access_results and not share_failed_hosts:
        print_info("No readable or writable SMB shares reported for the Standard User.")

    if unknown_hosts:

        print_warning(
            "SMB configuration could not be fully assessed on "
            f"{len({host.casefold() for host in unknown_hosts})} host(s). "
            "See the HTML report for details."
        )

    if anonymous_failed_hosts:
        print_warning(
            "SMB anonymous enumeration could not be completed on "
            f"{len({host.casefold() for host in anonymous_failed_hosts})} host(s). "
            "See the HTML report for details."
        )

    if share_failed_hosts:
        print_warning(
            "SMB share-access checks could not be completed on "
            f"{len({host.casefold() for host in share_failed_hosts})} host(s). "
            "See the HTML report for details."
        )

    (get_artefacts_dir() / "findings-smb-unknown-hosts.txt").write_text(
        "\n".join(sorted(unknown_hosts)) + ("\n" if unknown_hosts else ""),
        encoding="utf-8",
    )

    if smb_signing_disabled:

        finding = load_finding("smb", "SMB-001")
        finding.affected_assets.extend(sorted(set(smb_signing_disabled)))
        findings.append(finding)

    if smbv1_enabled:

        finding = load_finding("smb", "SMB-002")
        finding.affected_assets.extend(sorted(set(smbv1_enabled)))
        findings.append(finding)

    if anonymous_enumeration:

        finding = load_finding("smb", "SMB-003")

        for result in anonymous_enumeration:

            host = result["host"]
            share_count = result["anonymous_shares"]
            user_count = result["anonymous_users"]

            if share_count:
                finding.evidence.append(
                    f"Unauthenticated SMB access on '{host}' enumerated "
                    f"{share_count} share(s)."
                )

            if user_count:
                finding.evidence.append(
                    f"Unauthenticated SAMR access on '{host}' returned "
                    f"{user_count} account(s), as reported by NetExec."
                )

            finding.affected_assets.append(host)

        finding.affected_assets = sorted(set(finding.affected_assets))
        findings.append(finding)

    writable_shares = [
        (result["host"], share)
        for result in share_access_results
        for share in result["shares"]
        if any(permission.startswith("WRITE") for permission in share["permissions"])
    ]
    if writable_shares:

        finding = load_finding("smb", "SMB-004")

        for host, share in writable_shares:
            finding.affected_assets.append(host)
            finding.evidence.append(
                f"NetExec reported {', '.join(share['permissions'])} permissions "
                f"for Standard User '{standard_user}' on share '{share['name']}' "
                f"on '{host}'."
            )

        finding.affected_assets = sorted(set(finding.affected_assets))
        findings.append(finding)

    record_findings(findings)

    return std_pass

def run_asreproast_checks(
    std_pass: str | None = None,
) -> str | None:
    """
    Execute AS-REP roasting checks and correlate matches with privileged groups.

    AS-REP enumeration remains unauthenticated. Standard User credentials are
    requested only when matching accounts need to be checked for privileged
    group membership.
    """

    session_data = require_session()
    require_collected_data(session_data, "domain_users_exported", "Domain user")

    print_section("AS-REP Roasting")

    with progress("Checking for AS-REP roastable accounts..."):

        asrep_results, findings = (
            asreproast_check(
                session_data["dc_ip"],
                session_data["domain"],
            )
        )

    record_findings(findings)
    privileged_accounts: list[str] = []
    privileged_assessed = True
    if asrep_results["accounts"]:
        try:
            if std_pass is None:
                std_pass = authenticate_standard_user()

            with progress(
                "Checking AS-REP roastable accounts for privileged group "
                "membership..."
            ):
                privileged_accounts, privileged_findings = (
                    asreproast_privileged_check(
                        session_data["dc_ip"],
                        asrep_results["accounts"],
                        session_data["standard_user"],
                        std_pass,
                    )
                )
            record_findings(privileged_findings)
        except CheckExecutionError as exc:
            record_incomplete("AS-REP privileged membership", "", str(exc))
            privileged_assessed = False

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row(
        "AS-REP Roastable Accounts",
        str(asrep_results["account_count"]),
    )
    table.add_row(
        "Privileged AS-REP Roastable Accounts",
        str(len(privileged_accounts)) if privileged_assessed else "Unknown",
    )

    console.print(table)

    return std_pass
