from rich.table import Table

from ad_kit.checks.asreproast import (
    asreproast_check,
    asreproast_privileged_check,
)
from ad_kit.checks.ldap import ldap_check
from ad_kit.checks.smb import (
    smb_configuration_check,
    smb_writable_share_check,
)
from ad_kit.checks.tombstone import tombstone_check
from ad_kit.core.checks import load_dc_hostnames, load_domain_computers
from ad_kit.core.console import console, print_info, print_section
from ad_kit.core.findings import load_finding
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.util import (
    get_artefacts_dir, progress, require_collected_data, require_session,
)
from ad_kit.reporting.results import record_findings, record_incomplete

from .credentials import authenticate_standard_user


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

    with progress("Checking LDAP configuration..."):

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

    with progress("Checking Standard User access to deleted objects..."):

        for dc_ip in dc_ips:
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

def run_smb_checks(
    std_pass: str | None = None,
) -> str | None:
    """
    Execute SMB security checks against discovered hosts.

    This check evaluates SMB signing, SMBv1, anonymous enumeration, and
    standard-user write access to shares across discovered systems.

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

    hosts = load_domain_computers()

    with progress("Checking SMB configuration..."):

        for host in hosts:

            try:
                result = smb_configuration_check(
                    host,
                    session_data["dc_ip"],
                )
            except CheckExecutionError as exc:
                record_incomplete("SMB configuration", host, str(exc))
                unknown_hosts.append(host)
                continue

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
                    "SMB configuration", host, f"Unknown: {', '.join(unknown)}"
                )
            if len(unknown) == 3:
                continue

            smb_results.append(result)

    dcs = {
        dc.lower()
        for dc in load_dc_hostnames()
    }

    dc_results = []
    host_results = []

    for result in smb_results:

        if result["signing"] == "[red]✗ Disabled[/red]":

            smb_signing_disabled.append(result["host"])

        if result["smbv1"] == "[red]✗ Enabled[/red]":

            smbv1_enabled.append(result["host"])

        if result["anonymous_shares"] or result["anonymous_users"]:
            anonymous_enumeration.append(result)

        host = result["host"].lower()

        if host in dcs:
            dc_results.append(result)
        else:
            host_results.append(result)

    print_section("SMB Checks - Domain Controllers")

    dc_table = Table()

    dc_table.add_column("Host", style="cyan")
    dc_table.add_column("Signing", style="green")
    dc_table.add_column("SMBv1", style="green")
    dc_table.add_column("Anon Shares", style="yellow")
    dc_table.add_column("Anon Users", style="yellow")

    for result in dc_results:

        dc_table.add_row(
            result["host"],
            result["signing"],
            result["smbv1"],
            (
                str(result["anonymous_shares"])
                if result["anonymous_shares"] is not None
                else "N/A"
            ),
            (
                str(result["anonymous_users"])
                if result["anonymous_users"] is not None
                else "N/A"
            ),
        )

    console.print(dc_table)

    print_section("SMB Checks - Hosts")

    host_table = Table()

    host_table.add_column("Host", style="cyan")
    host_table.add_column("Signing", style="green")
    host_table.add_column("SMBv1", style="green")
    host_table.add_column("Anon Shares", style="yellow")
    host_table.add_column("Anon Users", style="yellow")

    for result in host_results:

        host_table.add_row(
            result["host"],
            result["signing"],
            result["smbv1"],
            (
                str(result["anonymous_shares"])
                if result["anonymous_shares"] is not None
                else "N/A"
            ),
            (
                str(result["anonymous_users"])
                if result["anonymous_users"] is not None
                else "N/A"
            ),
        )

    console.print(host_table)

    writable_share_results = []
    writable_failed_hosts = []
    standard_user = session_data.get("standard_user", "")
    writable_checks_run = False
    if hosts:
        if standard_user:
            if std_pass is None:
                try:
                    std_pass = authenticate_standard_user()
                except CheckExecutionError as exc:
                    record_incomplete("SMB writable shares", "all hosts", str(exc))
            if std_pass is not None:
                writable_checks_run = True

            if writable_checks_run:
                with progress("Checking writable SMB shares..."):

                    for host in hosts:

                        try:
                            shares = smb_writable_share_check(
                                host,
                                session_data["dc_ip"],
                                standard_user,
                                std_pass,
                            )
                        except CheckExecutionError as exc:
                            record_incomplete("SMB writable shares", host, str(exc))
                            writable_failed_hosts.append(host)
                            continue

                        if shares:
                            writable_share_results.append({
                                "host": host,
                                "shares": shares,
                            })
        else:
            record_incomplete(
                "SMB writable shares", "all hosts",
                "No Standard User is configured for this session",
            )

    print_section("SMB Checks - Writable Shares")

    writable_table = Table()
    writable_table.add_column("Host", style="cyan")
    writable_table.add_column("Share / Permissions", style="yellow")

    for result in writable_share_results:

        for share in result["shares"]:
            writable_table.add_row(result["host"], share)

    console.print(writable_table)

    if writable_checks_run and not writable_share_results and not writable_failed_hosts:
        print_info("No writable SMB shares found for the Standard User.")

    if unknown_hosts:

        print_info(
            f"Unable to determine SMB configuration for {len(unknown_hosts)} "
            "host(s)."
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

    if writable_share_results:

        finding = load_finding("smb", "SMB-004")

        for result in writable_share_results:

            host = result["host"]
            finding.affected_assets.append(host)

            for share in result["shares"]:
                finding.evidence.append(
                    f"NetExec reported WRITE access for Standard User "
                    f"'{standard_user}' to '{share}' on "
                    f"'{host}'."
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
