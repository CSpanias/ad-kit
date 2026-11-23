import re
import sys

import questionary
import typer
from rich.table import Table

from ad_kit.checks.adcs import SUPPORTED_ESC_CLASSES, adcs_check
from ad_kit.checks.builtin_accounts import builtin_accounts_check
from ad_kit.checks.coercion import coercion_check, extract_hostname
from ad_kit.checks.dcsync import DCSyncTrustee, dcsync_check, dcsync_findings
from ad_kit.checks.delegations import delegation_check
from ad_kit.checks.kerberoast import kerberoast_check
from ad_kit.checks.ldap_info import is_sensitive_value, ldap_info_check
from ad_kit.checks.privileged_excessive import (
    ADMIN_COUNT_THRESHOLD,
    PRIVILEGED_GROUP_THRESHOLD,
    privileged_excessive_check,
)
from ad_kit.core.checks import (
    capture_check_evidence,
    format_check_evidence,
    load_dc_hostnames,
)
from ad_kit.core.console import console, object_text, print_info, print_section
from ad_kit.core.exceptions import ADKitError
from ad_kit.core.findings import load_finding, load_finding_definition
from ad_kit.core.util import progress, require_session, save_session
from ad_kit.reporting.results import record_findings

from .credentials import authenticate_standard_user


def _expected_dcsync_sids(
    session_data: dict, trustees: list[DCSyncTrustee]
) -> set[str]:
    saved = session_data.get("expected_dcsync_sids", [])
    if not isinstance(saved, list) or not all(
        isinstance(sid, str) and re.fullmatch(r"S-\d+(?:-\d+)+", sid, re.IGNORECASE)
        for sid in saved
    ):
        raise ADKitError("Invalid expected DCSync SID list in assessment session.")
    expected = {sid.upper() for sid in saved}
    if not sys.stdin.isatty():
        if trustees and "expected_dcsync_sids" not in session_data:
            print_info("Run interactively to select expected DCSync trustees.")
        return expected

    choices = [
        questionary.Choice(
            title=f"{trustee['name']} ({trustee['sid']}) — {', '.join(trustee['rights'])}",
            value=trustee["sid"].upper(),
            checked=trustee["sid"].upper() in expected,
        )
        for trustee in trustees
    ]
    current_sids = {trustee["sid"].upper() for trustee in trustees}
    choices.extend(
        questionary.Choice(
            title=f"{sid} (not currently observed)", value=sid, checked=True
        )
        for sid in sorted(expected - current_sids)
    )
    if not choices:
        return expected
    selected = questionary.checkbox(
        "Select confirmed expected DCSync trustees (Space to select, Enter to confirm):",
        choices=choices,
    ).ask()
    if selected is None:
        raise typer.Abort()
    session_data["expected_dcsync_sids"] = sorted(selected)
    save_session(session_data)
    return set(selected)


def run_privileged_group_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute privileged group, DCSync-right, and built-in account checks.

    This check evaluates membership of selected privileged Active Directory
    groups, built-in account status, and non-default DCSync replication rights.

    Findings are generated where privileged group membership exceeds the 
    assessment threshold.
    """

    session_data = require_session()

    print_section("Privileged Group Membership")

    if std_pass is None:

        std_pass = authenticate_standard_user()

    with progress("Reviewing privileged group membership..."):

        privileged_results, findings = (
            privileged_excessive_check(
                session_data["dc_ip"],
                session_data["standard_user"],
                std_pass,
            )
        )
        record_findings(findings)
        builtin_accounts, builtin_account_findings = builtin_accounts_check(
            session_data["dc_ip"],
            session_data["domain"],
            session_data["standard_user"],
            std_pass,
        )
        record_findings(builtin_account_findings)
        administrative_accounts = {
            member
            for group_name in ("Domain Admins", "Enterprise Admins")
            for member in privileged_results["groups"][group_name]["members"]
        }
        try:
            dc_hostnames = load_dc_hostnames()
        except FileNotFoundError:
            dc_hostnames = []
            print_info(
                "Domain Controller hostname inventory is unavailable; "
                "excluding default controller groups only."
            )

        dcsync_trustees = dcsync_check(
            session_data["dc_ip"],
            session_data["domain"],
            session_data["standard_user"],
            std_pass,
            administrative_accounts,
            dc_hostnames,
        )

    expected_dcsync_sids = _expected_dcsync_sids(session_data, dcsync_trustees)
    dcsync_trustees = [
        trustee for trustee in dcsync_trustees
        if trustee["sid"].upper() not in expected_dcsync_sids
    ]
    record_findings(dcsync_findings(dcsync_trustees))

    table = Table()

    table.add_column("Group / Indicator", style="cyan")
    table.add_column("Members", style="green")
    table.add_column("% Enabled Users", style="yellow")
    table.add_column("Assessment", style="red")

    for group, data in privileged_results["groups"].items():

        percentage = data["percentage"]

        table.add_row(
            group,
            str(data["member_count"]),
            f"{percentage:.1f}%",
            (
                "[red]✗ Excessive[/red]"
                if percentage >= PRIVILEGED_GROUP_THRESHOLD
                else "[green]✓ Normal[/green]"
            ),
        )

    admin_count = privileged_results["admin_count"]
    table.add_row(
        "adminCount=1 accounts",
        str(admin_count["member_count"]),
        f"{admin_count['percentage']:.1f}%",
        (
            "[yellow]Review[/yellow]"
            if admin_count["percentage"] >= ADMIN_COUNT_THRESHOLD
            else "[green]✓ Normal[/green]"
        ),
    )

    console.print(table)

    excessive_members = [
        (group, data["members"])
        for group, data in privileged_results["groups"].items()
        if data["percentage"] >= PRIVILEGED_GROUP_THRESHOLD and data["members"]
    ]
    if (
        admin_count["percentage"] >= ADMIN_COUNT_THRESHOLD
        and admin_count["members"]
    ):
        excessive_members.append(("adminCount=1 accounts", admin_count["members"]))
    if excessive_members:
        members_table = Table(title="Accounts Requiring Review")
        members_table.add_column("Group / Indicator", style="cyan")
        members_table.add_column("Object", style="yellow")
        for group, members in excessive_members:
            members_table.add_row(group, object_text(members))
        console.print()
        console.print(members_table)

    account_table = Table(title="Built-in Account Status")
    account_table.add_column("Account", style="cyan")
    account_table.add_column("sAMAccountName", style="green")
    account_table.add_column("Status", style="yellow")

    for account_key, label in (
        ("administrator", "Administrator (RID 500)"),
        ("guest", "Guest (RID 501)"),
    ):
        account = builtin_accounts[account_key]
        enabled = account["enabled"]
        status = (
            "[yellow]Unknown[/yellow]"
            if enabled is None
            else "[yellow]Enabled[/yellow]"
            if enabled and account_key == "administrator"
            else "[red]Enabled[/red]"
            if enabled
            else "[green]Disabled[/green]"
        )
        account_table.add_row(label, account["account_name"], status)

    console.print()
    console.print(account_table)

    dcsync_table = Table(title="Unexpected DCSync Principals")
    dcsync_table.add_column("Trustee", style="cyan")
    dcsync_table.add_column("SID", style="green")
    dcsync_table.add_column("Replication Rights", style="yellow")
    dcsync_table.add_column("Core Right Set", style="red")

    if dcsync_trustees:
        for trustee in dcsync_trustees:
            dcsync_table.add_row(
                trustee["name"],
                trustee["sid"],
                ", ".join(trustee["rights"]),
                "Complete" if trustee["complete"] else "Partial",
            )
    else:
        dcsync_table.add_row("No unexpected trustees found", "", "", "")

    console.print()
    console.print(dcsync_table)

def run_delegation_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute Active Directory delegation assessment checks.

    This check identifies accounts configured for Unconstrained Delegation and 
    Kerberos Constrained Delegation with Protocol Transition.

    Findings are generated where delegation configurations introduce an 
    increased risk of impersonation, privilege escalation, or compromise of 
    privileged accounts.
    """

    session_data = require_session()

    print_section("Delegation")

    if std_pass is None:

        std_pass = authenticate_standard_user()

    with progress("Reviewing delegation configuration..."):

        delegation_results, findings = (
            delegation_check(
                session_data["dc_ip"],
                session_data["standard_user"],
                std_pass,
            )
        )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Object", style="yellow")

    table.add_row(
        "Unconstrained Delegation",
        str(len(delegation_results["unconstrained"])),
        object_text(delegation_results["unconstrained"]),
    )

    table.add_row(
        "Protocol Transition",
        str(len(delegation_results["protocol_transition"])),
        object_text(delegation_results["protocol_transition"]),
    )

    console.print(table)

    record_findings(findings)

def run_kerberoast_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute Kerberoasting assessment checks.

    This check identifies Active Directory accounts associated with Service 
    Principal Names (SPNs).

    Findings are generated where Kerberos service tickets can be requested and 
    subjected to offline password cracking attacks.
    """

    session_data = require_session()

    print_section("Kerberoasting")

    if std_pass is None:

        std_pass = authenticate_standard_user()

    with progress("Checking for Kerberoastable accounts..."):

        kerberoast_results, findings = (
            kerberoast_check(
                session_data["dc_ip"],
                session_data["domain"],
                session_data["standard_user"],
                std_pass,
            )
        )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Object", style="yellow")

    table.add_row(
        "Kerberoastable Accounts",
        str(kerberoast_results["account_count"]),
        object_text(kerberoast_results["accounts"]),
    )

    console.print(table)

    record_findings(findings)

def run_adcs_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute Active Directory Certificate Services (AD CS) assessment checks.

    This check identifies known ESC attack paths within ADCS certificate 
    templates and Certification Authorities.

    Findings are currently generated for ESC1, ESC8 and ESC15. Additional ESC
    classifications are reported for visibility.
    """

    session_data = require_session()

    print_section("Active Directory Certificate Services")

    if std_pass is None:

        std_pass = authenticate_standard_user()

    with progress("Reviewing AD CS configuration..."):

        adcs_results, findings = (
            adcs_check(
                session_data["dc_ip"],
                session_data["domain"],
                session_data["standard_user"],
                std_pass,
            )
        )

    table = Table()

    table.add_column("ESC Path", style="cyan")
    table.add_column("Count", style="green")
    table.add_column("Object", style="yellow")

    for esc in SUPPORTED_ESC_CLASSES:

        count = len(adcs_results.get(esc, []))

        if count == 0:
            continue

        table.add_row(esc, str(count), object_text(adcs_results[esc]))

    console.print(table)

    print_info(
        "Findings are currently generated for ESC1, ESC8 and ESC15. Other "
        "identified ESC classifications are reported for visibility only."
    )

    record_findings(findings)

def run_ldap_info_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute LDAP information exposure assessment checks.

    This check reviews commonly accessible LDAP attributes for potentially
    sensitive information, including account descriptions, informational
    fields, and password-related attributes.

    A finding is generated for keyword matches or returned password-attribute
    values, which require further review.
    """

    session_data = require_session()

    print_section("LDAP Information Exposure")

    if std_pass is None:

        std_pass = authenticate_standard_user()

    with progress("Reviewing LDAP attributes..."):

        ldap_info_results = (
            ldap_info_check(
                session_data["dc_ip"],
                session_data["standard_user"],
                std_pass,
            )
        )

    findings = []

    sensitive_attributes = []

    for entry in ldap_info_results["descriptions"]:

        if is_sensitive_value(entry["value"]):

            sensitive_attributes.append(
                (
                    entry["user"],
                    entry["value"],
                    "description",
                )
            )

    for entry in ldap_info_results["info_fields"]:

        if is_sensitive_value(entry["value"]):

            sensitive_attributes.append(
                (
                    entry["user"],
                    entry["value"],
                    "info",
                )
            )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Sensitive LDAP Attributes", str(len(sensitive_attributes)))
    table.add_row(
        "userPassword Values",
        str(len(ldap_info_results["user_passwords"])),
    )

    table.add_row(
        "unixUserPassword Values",
        str(len(ldap_info_results["unix_passwords"])),
    )

    console.print(table)

    exposed_accounts = [
        (user, attribute) for user, _, attribute in sensitive_attributes
    ]
    for attribute, lines in (
        ("userPassword", ldap_info_results["user_passwords"]),
        ("unixUserPassword", ldap_info_results["unix_passwords"]),
    ):
        for line in lines:
            match = re.search(
                r"\bUser:\s*(.*?)\s+" + re.escape(attribute) + r":",
                line,
                re.IGNORECASE,
            )
            if match and match.group(1).strip():
                exposed_accounts.append((match.group(1).strip(), attribute))

    if exposed_accounts:
        detail_table = Table(title="Affected LDAP Attributes")
        detail_table.add_column("Object", style="cyan")
        detail_table.add_column("Attribute", style="yellow")
        for user, attribute in sorted(set(exposed_accounts)):
            detail_table.add_row(object_text([user]), attribute)
        console.print()
        console.print(detail_table)

    attributes = {attribute for _, _, attribute in sensitive_attributes}
    if ldap_info_results["user_passwords"]:
        attributes.add("userPassword")
    if ldap_info_results["unix_passwords"]:
        attributes.add("unixUserPassword")

    if attributes:
        finding = load_finding("ldap_info", "LDAPINFO-001")
        definitions = load_finding_definition("ldap_info", "LDAPINFO-001")["settings"]
        commentary = []
        remediation = []
        references = []
        for attribute in ("description", "info", "userPassword", "unixUserPassword"):
            if attribute not in attributes:
                continue
            content = definitions[attribute]
            commentary.append("- " + content["commentary"])
            remediation.append("- " + content["remediation"])
            references.extend(content["references"])
        finding.commentary = finding.commentary.strip() + "\n\n" + "\n".join(commentary)
        finding.remediation = finding.remediation.strip() + "\n\n" + "\n".join(remediation)
        finding.references = list(dict.fromkeys(references))
        for user, value, attribute in sensitive_attributes:
            finding.evidence.append(
                f"Account `{user}` contained potentially sensitive information "
                f"within the LDAP `{attribute}` attribute: `{value}`."
            )
        finding.evidence.extend(
            ldap_info_results["user_passwords"] + ldap_info_results["unix_passwords"]
        )
        findings.append(finding)

    record_findings(findings)

def run_coercion_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute authentication coercion assessment checks.

    This check identifies hosts exposing authentication coercion techniques and 
    Domain Controllers with the Print Spooler service enabled.

    Findings are generated where systems expose coercion attack paths or
    unnecessary Print Spooler functionality on Domain Controllers.
    """

    session_data = require_session()

    print_section("Authentication Coercion")

    if std_pass is None:

        std_pass = authenticate_standard_user()

    with capture_check_evidence() as evidence, progress("Reviewing coercion attack paths..."):

        coercion_results = (
            coercion_check(
                session_data["standard_user"],
                std_pass,
            )
        )

    findings = []

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Object", style="yellow")

    table.add_row(
        "Coercible DCs",
        str(len(coercion_results["coercion_dcs"])),
        object_text(list(coercion_results["coercion_dcs"])),
    )

    table.add_row(
        "DCs with Print Spooler",
        str(len(coercion_results["spooler_dcs"])),
        object_text(coercion_results["spooler_dcs"]),
    )

    console.print(table)

    if coercion_results["coercion_dcs"] or coercion_results["spooler_dcs"]:

        finding = load_finding("coercion", "COERCE-001")

        for host, techniques in (coercion_results["coercion_dcs"].items()):

            finding.evidence.append(
                f"Domain Controller `{host}` exposed the following "
                "authentication coercion technique(s): "
                f"{', '.join(techniques)}."
            )

        for dc in coercion_results["spooler_dcs"]:

            finding.evidence.append(
                f"The Print Spooler service was enabled on Domain Controller "
                f"`{dc}`."
            )

        findings.append(finding)

    if findings:
        for name, marker, hosts in (
            ("coercion-plus", "VULNERABLE,", coercion_results["coercion_dcs"]),
            ("coercion-webdav", "WebClient Service enabled", coercion_results["coercion_dcs"]),
            ("coercion-spooler", "Spooler service enabled", coercion_results["spooler_dcs"]),
        ):
            record = next((item for item in evidence if item.name == name), None)
            if record is None:
                continue
            line = next(
                (
                    line for line in record.stdout.splitlines()
                    if marker in line and extract_hostname(line) in hosts
                ),
                None,
            )
            if line:
                print_section("Authentication Coercion - Command Evidence")
                console.print(format_check_evidence(record, line), markup=False, highlight=False)
                console.print()
                break

    record_findings(findings)
