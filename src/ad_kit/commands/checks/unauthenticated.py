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
from ad_kit.core.console import console, object_text, print_info, print_section, print_warning
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.finding import EvidenceTable, Finding
from ad_kit.core.findings import format_counted_commentary, load_finding
from ad_kit.core.util import (
    count_form,
    count_text,
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
) -> bool:
    sample: tuple[str, tuple[str, str], list[CheckEvidence]] | None = None
    best_rank = 3
    for result in results:
        host = result["dc_hostname"] if protocol == "ldap" else result["host"]
        permitted = (
            result["anonymous_bind"] == "[red]✗ Permitted[/red]"
            if protocol == "ldap"
            else result["null_auth"] is True or result.get("guest_auth", False)
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
        return False
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
    return True


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
        std_pass = authenticate_standard_user(trailing_blank=False)

    dc_ips = sorted(set(session_data.get("dc_ips") or [session_data["dc_ip"]]))
    results = []
    findings = []

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
    table.add_column("Named Objects", style="yellow")

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
            object_text(
                result["sam_account_names"]
                if deleted_objects is not None and deleted_objects > 0
                else []
            ),
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
        affected = {result["dc_hostname"].rstrip(".").casefold() for result in accessible_objects}
        format_counted_commentary(
            finding, len(affected), "Domain Controller (DC)", "Domain Controllers (DCs)"
        )

        for result in accessible_objects:
            dc_hostname = result["dc_hostname"]
            deleted_objects = result["deleted_objects"]
            evidence = (
                f"Standard User '{standard_user}' enumerated "
                f"{count_text(deleted_objects)} deleted "
                f"{count_form(deleted_objects, 'object', 'objects')} "
                f"on '{dc_hostname}'."
            )
            sam_account_names = result["sam_account_names"]
            if sam_account_names:
                evidence += (
                    " Returned `sAMAccountName` values:\n"
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

def _anonymous_enumeration_status(result: dict, *, enumerate_users: bool) -> str:
    if result["anonymous_shares"] or result["anonymous_users"]:
        return "Guest" if result.get("guest_auth", False) else "Enabled"
    if result["null_auth"] is False:
        return "Disabled"
    if (
        (result["null_auth"] is True or result.get("guest_auth", False))
        and result["anonymous_shares"] == 0
        and (
            not enumerate_users
            or (
                result["anonymous_users"] == 0
                and result.get("anonymous_users_complete", False)
            )
        )
        and not result["anonymous_incomplete"]
    ):
        return "Disabled"
    return "Unknown"


def _summarise_smb_systems(finding: Finding, hosts: list[str], dcs: set[str]) -> None:
    finding.affected_assets.extend(sorted(set(hosts)))
    count = len(finding.affected_assets)
    dc_count = sum(host.rstrip(".").casefold() in dcs for host in finding.affected_assets)
    finding.commentary = finding.commentary.format(
        count=count_text(count),
        subject=count_form(count, "system", "systems"),
        dc_summary=(
            f", including {count_text(dc_count)} "
            f"{count_form(dc_count, 'domain controller', 'domain controllers')},"
            if dc_count else ""
        ),
    )
    finding.show_affected_assets = False


def _anonymous_count(
    count: int | None, null_auth: bool | None, *, complete: bool = True
) -> str:
    if not complete and count is not None:
        return f"Incomplete ({count} observed)"
    if count is not None:
        return str(count)
    return "[green]✓ Denied[/green]" if null_auth is False else "Incomplete"


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

    findings = []

    smb_signing_disabled = []
    smbv1_enabled = []
    anonymous_enumeration = []

    unknown_hosts = []
    anonymous_failed_hosts = []

    hosts = load_domain_computers()
    dcs = {dc.rstrip(".").casefold() for dc in load_dc_hostnames()}
    targets = unique_hosts(hosts)
    dc_targets = [host for host in targets if host.rstrip(".").casefold() in dcs]
    host_targets = [host for host in targets if host.rstrip(".").casefold() not in dcs]

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

    def check_configuration_batch(
        batch: list[str], label: str
    ) -> tuple[list[dict], list[CheckEvidence]]:
        if not batch:
            return [], []
        batch_results = []
        with (
            capture_check_evidence() as evidence,
            progress(f"Checking SMB configuration for {label}..."),
        ):
            checked = parallel_items(batch, f"SMB configuration {label}", check_host)
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
                    (
                        result["null_auth"] is None and not result.get("guest_auth", False),
                        "anonymous access",
                    ),
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
            if (result["null_auth"] or result.get("guest_auth", False)) and (
                result["anonymous_incomplete"]
                or result["anonymous_shares"] is None
                or (
                    is_dc
                    and not result.get(
                        "anonymous_users_complete", result["anonymous_users"] is not None
                    )
                )
            ):
                anonymous_failed_hosts.append(result["host"])

            batch_results.append(result)
        return batch_results, evidence

    dc_results, dc_evidence = check_configuration_batch(dc_targets, "Domain Controllers")

    print_section("SMB Checks - Domain Controllers")

    dc_table = Table()

    dc_table.add_column("Host", style="cyan")
    dc_table.add_column("Signing", style="green")
    dc_table.add_column("SMBv1", style="green")
    dc_table.add_column("Anonymous Enumeration")
    show_shares = any(result["anonymous_shares"] for result in dc_results)
    show_users = any(result["anonymous_users"] for result in dc_results)
    if show_shares:
        dc_table.add_column("Anon Shares (count)", style="yellow")
    if show_users:
        dc_table.add_column("Anon Users (count)", style="yellow")

    for result in dc_results:
        status = _anonymous_enumeration_status(result, enumerate_users=True)
        row = [
            result["host"],
            result["signing"],
            result["smbv1"],
            {
                "Enabled": "[red]✗ Enabled[/red]",
                "Disabled": "[green]✓ Disabled[/green]",
                "Unknown": "[yellow]⚠ Unknown[/yellow]",
                "Guest": "[yellow]⚠ Guest[/yellow]",
            }[status],
        ]
        if show_shares:
            row.append(_anonymous_count(result["anonymous_shares"], result["null_auth"]))
        if show_users:
            row.append(_anonymous_count(
                result["anonymous_users"],
                result["null_auth"],
                complete=result.get("anonymous_users_complete", True),
            ))
        dc_table.add_row(*row)

    console.print(dc_table)
    dc_evidence_shown = _show_anonymous_evidence(
        dc_evidence,
        [
            result for result in dc_results
            if result["anonymous_shares"] or result["anonymous_users"]
        ],
        "smb",
    )

    host_results, host_evidence = check_configuration_batch(host_targets, "hosts")

    print_section("SMB Checks - Hosts")

    host_table = Table()

    host_table.add_column("Check", style="cyan")
    host_table.add_column("Enabled", justify="right")
    host_table.add_column("Disabled", justify="right")
    host_table.add_column("Unknown", justify="right")
    statuses = [
        _anonymous_enumeration_status(result, enumerate_users=False)
        for result in host_results
    ]
    guest = statuses.count("Guest")
    if guest:
        host_table.add_column("Guest", justify="right")

    for label, key in (("SMB Signing", "signing"), ("SMBv1", "smbv1")):
        enabled_status = "[green]✓ Enabled[/green]" if key == "signing" else "[red]✗ Enabled[/red]"
        disabled_status = (
            "[red]✗ Disabled[/red]" if key == "signing" else "[green]✓ Disabled[/green]"
        )
        enabled = sum(result[key] == enabled_status for result in host_results)
        disabled = sum(result[key] == disabled_status for result in host_results)
        row = [label, str(enabled), str(disabled), str(len(host_targets) - enabled - disabled)]
        if guest:
            row.append("-")
        host_table.add_row(*row)

    enabled = statuses.count("Enabled")
    disabled = statuses.count("Disabled")
    row = [
        "Anonymous Enumeration", str(enabled), str(disabled),
        str(len(host_targets) - enabled - disabled - guest),
    ]
    if guest:
        row.append(str(guest))
    host_table.add_row(*row)

    console.print(host_table)
    if unknown_hosts:
        count = len({host.casefold() for host in unknown_hosts})
        print_warning(
            "SMB configuration could not be fully assessed on "
            f"{count} {count_form(count, 'host', 'hosts')}. "
            "See the HTML report for details."
        )

    if anonymous_failed_hosts:
        count = len({host.casefold() for host in anonymous_failed_hosts})
        print_warning(
            "SMB anonymous enumeration could not be completed on "
            f"{count} {count_form(count, 'host', 'hosts')}. "
            "See the HTML report for details."
        )

    if not dc_evidence_shown:
        _show_anonymous_evidence(
            host_evidence,
            [
                result for result in host_results
                if result["anonymous_shares"] or result["anonymous_users"]
            ],
            "smb",
        )
    else:
        console.print()

    for result in dc_results + host_results:
        if result["signing"] == "[red]✗ Disabled[/red]":
            smb_signing_disabled.append(result["host"])
        if result["smbv1"] == "[red]✗ Enabled[/red]":
            smbv1_enabled.append(result["host"])
        if result["anonymous_shares"] or result["anonymous_users"]:
            anonymous_enumeration.append(result)

    share_access_results = []
    share_failed_hosts = []
    standard_user = session_data.get("standard_user", "")
    share_checks_run = False
    if hosts:
        if standard_user:
            if std_pass is None:
                try:
                    std_pass = authenticate_standard_user(trailing_blank=False)
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
    share_table.add_column("Shares", style="yellow")
    share_table.add_column("Permissions", style="yellow")

    displayed_shares = False
    for result in share_access_results:
        grouped: dict[tuple[str, ...], list[str]] = {}
        for share in result["shares"]:
            if (
                share["name"].casefold() in {"ipc$", "print$"}
                and share["permissions"] == ("READ",)
            ):
                continue
            grouped.setdefault(share["permissions"], []).append(share["name"])

        for index, (permissions, names) in enumerate(grouped.items()):
            displayed_shares = True
            share_table.add_row(
                result["host"] if index == 0 else "",
                Text(", ".join(names)),
                ", ".join(permissions),
            )

    console.print(share_table)
    console.print()

    if share_checks_run:
        if not displayed_shares and not share_failed_hosts:
            print_info("No reportable SMB shares found for the Standard User.")
        print_info(
            "Read-only IPC$ and print$ shares are omitted; writable entries remain visible. "
            "Full command output is available in the evidence directory."
        )

    if share_failed_hosts:
        count = len({host.casefold() for host in share_failed_hosts})
        print_warning(
            "SMB share-access checks could not be completed on "
            f"{count} {count_form(count, 'host', 'hosts')}. "
            "See the HTML report for details."
        )

    (get_artefacts_dir() / "findings-smb-unknown-hosts.txt").write_text(
        "\n".join(sorted(unknown_hosts)) + ("\n" if unknown_hosts else ""),
        encoding="utf-8",
    )

    if smb_signing_disabled:

        finding = load_finding("smb", "SMB-001")
        _summarise_smb_systems(finding, smb_signing_disabled, dcs)
        findings.append(finding)

    if smbv1_enabled:

        finding = load_finding("smb", "SMB-002")
        _summarise_smb_systems(finding, smbv1_enabled, dcs)
        findings.append(finding)

    if anonymous_enumeration:

        finding = load_finding("smb", "SMB-003")
        observed_shares = any(result["anonymous_shares"] for result in anonymous_enumeration)
        observed_users = any(result["anonymous_users"] for result in anonymous_enumeration)
        if observed_shares and observed_users:
            enumerated_information = "share names and user account information"
        elif observed_shares:
            enumerated_information = "share names"
        else:
            enumerated_information = "user account information"
        count = len(anonymous_enumeration)
        guest_sessions = any(result.get("guest_auth", False) for result in anonymous_enumeration)
        null_sessions = any(not result.get("guest_auth", False) for result in anonymous_enumeration)
        if guest_sessions and null_sessions:
            session_description = "anonymous and Guest-mapped SMB sessions"
        elif guest_sessions:
            session_description = count_form(
                count, "a Guest-mapped SMB session", "Guest-mapped SMB sessions"
            ) + " established with empty credentials"
        else:
            session_description = count_form(count, "an SMB null session", "SMB null sessions")
        all_dcs = all(
            result["host"].rstrip(".").casefold() in dcs
            for result in anonymous_enumeration
        )
        subject = (
            count_form(count, "domain controller", "domain controllers")
            if all_dcs else count_form(count, "system", "systems")
        )
        finding.commentary = finding.commentary.format(
            enumerated_information=enumerated_information,
            session_description=session_description,
            count=count_text(count),
            subject=subject,
            share_access_caveat=(
                " Enumerating share names does not by itself demonstrate access to "
                "share contents." if observed_shares else ""
            ),
        )
        finding.show_affected_assets = False
        finding.show_evidence = False

        for result in anonymous_enumeration:

            host = result["host"]
            share_count = result["anonymous_shares"]
            user_count = result["anonymous_users"]
            access = (
                "SMB access mapped to Guest with empty credentials"
                if result.get("guest_auth", False)
                else "Unauthenticated SMB access"
            )

            if share_count:
                finding.evidence.append(
                    f"{access} on '{host}' enumerated "
                    f"{count_text(share_count)} {count_form(share_count, 'share', 'shares')}."
                )

            if user_count:
                account_access = (
                    access if result.get("guest_auth", False)
                    else "Unauthenticated account enumeration"
                )
                finding.evidence.append(
                    f"{account_access} on '{host}' returned "
                    f"{count_text(user_count)} {count_form(user_count, 'account', 'accounts')}, "
                    "as reported by NetExec."
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
        finding.commentary = finding.commentary.format(
            share_description=count_form(
                len(writable_shares),
                "one Server Message Block (SMB) share",
                "multiple Server Message Block (SMB) shares",
            )
        )
        finding.show_affected_assets = False
        grouped_shares: dict[tuple[str, frozenset[str]], list[ShareAccess]] = {}
        for host, share in writable_shares:
            grouped_shares.setdefault((host, frozenset(share["permissions"])), []).append(share)
        finding.evidence_table = EvidenceTable(
            introduction=(
                "The following shares had write-related permissions reported "
                f"for Standard User '{standard_user}':"
            ),
            columns=("Hostname or IP address", "Share(s)", "Permissions"),
            rows=[
                (
                    host,
                    ", ".join(share["name"] for share in shares),
                    ", ".join(shares[0]["permissions"]),
                )
                for (host, _permissions), shares in grouped_shares.items()
            ],
        )

        for host, share in writable_shares:
            finding.affected_assets.append(host)

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
    table.add_column("Object", style="yellow")

    table.add_row(
        "AS-REP Roastable Accounts",
        str(asrep_results["account_count"]),
        object_text(asrep_results["accounts"]),
    )
    table.add_row(
        "Privileged AS-REP Roastable Accounts",
        str(len(privileged_accounts)) if privileged_assessed else "Unknown",
        object_text(privileged_accounts) if privileged_assessed else "Unknown",
    )

    console.print(table)

    return std_pass
