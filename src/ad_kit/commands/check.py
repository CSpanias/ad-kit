"""
Assessment workflow orchestration.

This module coordinates the execution of Active Directory assessment checks, 
credential validation, result presentation, finding generation, and Markdown 
report creation.

Checks are grouped into authenticated and unauthenticated categories and are 
executed through a consistent workflow that includes result collection,
assessment logic, finding generation, and evidence preservation.

Generated findings are exported to Markdown reports and supported by raw 
command output captured within the assessment evidence directory.
"""

import typer

from rich.table import Table

from ad_kit.checks.adcs import adcs_check, SUPPORTED_ESC_CLASSES
from ad_kit.core.checks import (
    load_domain_computers,
    load_dc_hostnames,
    validate_credentials,
    cleanup_test_artifact
)
from ad_kit.checks.asreproast import asreproast_check
from ad_kit.checks.coercion import coercion_check
from ad_kit.checks.delegations import delegation_check
from ad_kit.checks.ldap import ldap_check
from ad_kit.checks.ldap_info import ldap_info_check, is_sensitive_value
from ad_kit.checks.local_admin import local_admin_check
from ad_kit.checks.maq import maq_check
from ad_kit.checks.passwords import (
    password_policy_check, 
    password_policy_assessment
)
from ad_kit.checks.smb import smb_configuration_check
from ad_kit.checks.kerberoast import kerberoast_check
from ad_kit.checks.dns import dns_record_creation_check
from ad_kit.checks.pre2k import pre2k_check
from ad_kit.checks.privileged_excessive import privileged_excessive_check
from ad_kit.core.console import (
    console, 
    print_section, 
    print_error, 
    print_success
)
from ad_kit.core.findings import load_finding
from ad_kit.core.util import (
    progress, 
    get_artefacts_dir, 
    print_info,
    require_session,
)
from ad_kit.reporting.markdown import write_markdown_report


#-------------------------------------------------------------------------------
# UNAUTHENTICATED CHECKS
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# LDAP SIGNING & CHANNEL BINDING
#-------------------------------------------------------------------------------

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

    write_markdown_report(
        ldap_findings,
        get_artefacts_dir() / "findings-ldap.md",
    )

#-------------------------------------------------------------------------------
# SMB SIGNING & SMBv1
#-------------------------------------------------------------------------------

def run_smb_checks() -> None:
    """
    Execute SMB security checks against discovered hosts.

    This check evaluates SMB signing requirements and SMBv1 support across 
    Domain Controllers and domain joined systems. Results are grouped by asset 
    type and displayed in tabular format.

    Findings are intended to identify legacy SMB configurations and systems 
    vulnerable to common relay or downgrade attacks.
    """

    session_data = require_session()

    smb_results = []
    findings = []

    smb_signing_disabled = []
    smbv1_enabled = []

    unknown_hosts = []

    with progress("Checking SMB configuration..."):

        for host in load_domain_computers():

            result = smb_configuration_check(
                host,
                session_data["dc_ip"],
            )

            if (
                result["signing"] == "[yellow]⚠ Unknown[/yellow]"
                and result["smbv1"] == "[yellow]⚠ Unknown[/yellow]"
            ):
                unknown_hosts.append(result["host"])
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

    for result in dc_results:

        dc_table.add_row(
            result["host"],
            result["signing"],
            result["smbv1"],
        )

    console.print(dc_table)

    print_section("SMB Checks - Hosts")

    host_table = Table()

    host_table.add_column("Host", style="cyan")
    host_table.add_column("Signing", style="green")
    host_table.add_column("SMBv1", style="green")

    for result in host_results:

        host_table.add_row(
            result["host"],
            result["signing"],
            result["smbv1"],
        )

    console.print(host_table)

    if unknown_hosts:

        print_info(
            f"Unable to determine SMB configuration for {len(unknown_hosts)} "
            "host(s)."
        )

        (
            get_artefacts_dir()
            / "findings-smb-unknown-hosts.txt"
        ).write_text(
            "\n".join(
                sorted(unknown_hosts)
            ) + "\n",
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

    write_markdown_report(
        findings,
        get_artefacts_dir() / "findings-smb.md",
    )

#-------------------------------------------------------------------------------
# AS-REP ROASTING
#-------------------------------------------------------------------------------

def run_asreproast_checks() -> None:
    """
    Execute AS-REP roasting assessment checks.

    This check identifies Active Directory accounts configured without Kerberos 
    pre-authentication.

    Findings are generated where accounts are susceptible to AS-REP roasting 
    attacks.
    """

    session_data = require_session()

    print_section("AS-REP Roasting")

    with progress("Checking for AS-REP roastable accounts..."):

        asrep_results, findings = (
            asreproast_check(
                session_data["dc_ip"],
                session_data["domain"],
            )
        )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row(
        "AS-REP Roastable Accounts",
        str(asrep_results["account_count"]),
    )

    console.print(table)

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-asreproast.md",
    )

#-------------------------------------------------------------------------------
# AUTHENTICATED CHECKS
#-------------------------------------------------------------------------------

def authenticate_standard_user() -> str:
    """
    Prompt for and validate Standard User credentials.

    The user is prompted to enter the password for the Standard User account 
    stored in the assessment session. Authentication is validated against the
    target domain before authenticated checks are executed.

    Returns:
        The validated Standard User password.

    Raises:
        RuntimeError:
            If authentication cannot be completed.
    """

    session_data = require_session()

    while True:

        std_pass = typer.prompt(
            "Standard User Password",
            hide_input=True,
        )

        console.print()

        with progress("Validating credentials..."):

            status = validate_credentials(
                session_data["dc_ip"],
                session_data["standard_user"],
                std_pass,
            )

        if status == "valid":
            print_success("Authentication succeeded.")
            return std_pass

        if status == "locked":
            print_error("Account is locked out.")

        elif status == "invalid":
            print_error("Invalid credentials.")

        else:
            print_error("Unable to validate credentials.")

        if not typer.confirm(
            "Try again?",
            default=True,
        ):
            raise RuntimeError("Authentication cancelled.")


def authenticate_domain_admin() -> tuple[str, str]:
    """
    Prompt for and validate Domain Administrator (DA) credentials.

    The user is prompted to provide credentials for a DA account. 
    Authentication is validated against the target domain before the 
    credentials are returned to the caller.

    Returns:
        Tuple containing:

        - Domain Administrator username
        - Domain Administrator password

    Raises:
        RuntimeError:
            If authentication cannot be completed.
    """

    session_data = require_session()

    while True:

        da_user = typer.prompt("Domain Administrator Username")

        da_pass = typer.prompt("Domain Administrator Password", hide_input=True)

        console.print()

        with progress("Validating credentials..."):

            status = validate_credentials(
                session_data["dc_ip"],
                da_user,
                da_pass,
            )

        if status == "valid":

            print_success("Authentication succeeded.")

            return da_user, da_pass

        if status == "locked":

            print_error("Account is locked out.")

        elif status == "invalid":

            print_error("Invalid credentials.")

        else:

            print_error("Unable to validate credentials.")

        if not typer.confirm("Try again?", default=True):
            raise RuntimeError("Authentication cancelled.")

#-------------------------------------------------------------------------------
# LOCAL ADMINISTRATOR ACCESS
#-------------------------------------------------------------------------------

def run_local_admin_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute local administrator access assessment checks.

    This check determines whether the supplied standard user account possesses
    local administrator privileges on any domain-joined systems.

    Findings are generated where local administrative access is identified on
    member servers, workstations, or Domain Controllers.
    """

    session_data = require_session()

    print_section("Local Administrator Access")

    if std_pass is None:

        std_pass = authenticate_standard_user()

    with progress("Checking local administrator access..."):

        local_admin_results = (
            local_admin_check(
                session_data["dc_ip"],
                session_data["domain"],
                session_data["standard_user"],
                std_pass,
            )
        )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Hosts", str(len(local_admin_results["hosts"])))

    table.add_row(
        "Domain Controllers",
        str(len(local_admin_results["domain_controllers"])),
    )

    console.print(table)

    findings = []

    if local_admin_results["hosts"]:

        finding = load_finding("local_admin", "LA-001")

        for host in local_admin_results["hosts"]:

            finding.evidence.append(
                f"Authenticated user `{session_data['standard_user']}` "
                f"was identified as a local administrator on `{host}`."
            )

        finding.evidence.append(
            f"A total of {len(local_admin_results['hosts'])} host(s) permitted "
            "local administrator access."
        )

        findings.append(finding)

    if local_admin_results["domain_controllers"]:

        finding = load_finding("local_admin", "LA-002")

        for host in local_admin_results["domain_controllers"]:

            finding.evidence.append(
                f"Authenticated user `{session_data['standard_user']}` "
                "was identified as an administrator on Domain Controller "
                f"`{host}`."
            )

        finding.evidence.append(
            f"A total of {len(local_admin_results['domain_controllers'])} "
            "Domain Controller(s) permitted administrative access."
        )

        findings.append(finding)

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-local-admin.md",
    )

#-------------------------------------------------------------------------------
# PASSWORD POLICY
#-------------------------------------------------------------------------------

def run_password_policy_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute password policy assessment checks.

    This check authenticates using a valid domain account and retrieves the 
    effective domain password policy. Configuration settings are assessed 
    against common Active Directory security practices and the results are 
    displayed in tabular format.

    Assessed settings include password length, password history, complexity 
    requirements, account lockout configuration, and password age settings.
    """

    session_data = require_session()

    print_section("Password Policy")

    if std_pass is None:
        std_pass = authenticate_standard_user()

    with progress("Retrieving password policy..."):

        password_policy = password_policy_check(
            session_data["dc_ip"],
            session_data["standard_user"],
            std_pass,
        )

    assessment = password_policy_assessment(password_policy)

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Assessment", style="yellow")

    table.add_row(
        "Minimum Length",
        password_policy["minimum_length"],
        assessment["minimum_length"],
    )

    table.add_row(
        "Password History",
        password_policy["password_history"],
        assessment["password_history"],
    )

    table.add_row(
        "Maximum Age",
        password_policy["maximum_age"],
        assessment["maximum_age"],
    )

    table.add_row(
        "Minimum Age",
        password_policy["minimum_age"],
        assessment["minimum_age"],
    )

    table.add_row(
        "Complexity",
        password_policy["complexity"],
        assessment["complexity"],
    )

    table.add_row(
        "Observation Window",
        password_policy["observation_window"],
        assessment["observation_window"],
    )

    table.add_row(
        "Lockout Threshold",
        password_policy["lockout_threshold"],
        assessment["lockout_threshold"],
    )

    table.add_row(
        "Lockout Duration",
        password_policy["lockout_duration"],
        assessment["lockout_duration"],
    )

    console.print(table)

    findings = []

    policy_evidence = []

    # Build password policy evidence
    if assessment["minimum_length"] != "[green]✓ OK[/green]":

        policy_evidence.append(
            "Minimum password length was configured as "
             f"{password_policy['minimum_length']} characters, which is below "
             "the recommended best practice."
        )

    if assessment["password_history"] != "[green]✓ OK[/green]":

        policy_evidence.append(
            "Password history retained only "
            f"{password_policy['password_history']} previous password(s), "
            "increasing the likelihood of password reuse."
        )

    if assessment["minimum_age"] != "[green]✓ OK[/green]":

        policy_evidence.append(
            "Minimum password age was not configured, allowing users to "
                "rapidly change passwords and potentially circumvent password "
                "history controls."
        )

    if assessment["maximum_age"] != "[green]✓ OK[/green]":

        policy_evidence.append(
            "Maximum password age was not configured, resulting in passwords "
            "that may remain unchanged indefinitely."
        )

    if assessment["complexity"] != "[green]✓ OK[/green]":

        policy_evidence.append(
            "Password complexity requirements were disabled, allowing weak or "
            "easily guessable passwords to be configured."
        )

    # Build lockout policy evidence
    if assessment["observation_window"] != "[green]✓ OK[/green]":

        policy_evidence.append(
            "The account lockout observation window was configured as "
            f"{password_policy['observation_window']}, which may provide "
            "insufficient protection against password guessing attacks."
        )

    if assessment["lockout_duration"] != "[green]✓ OK[/green]":

        policy_evidence.append(
            "The account lockout duration was configured as "
            f"{password_policy['lockout_duration']}, which is below the "
            "recommended baseline."
        )

    if assessment["lockout_threshold"] != "[green]✓ OK[/green]":

        policy_evidence.append(
            "The account lockout threshold was configured as "
            f"{password_policy['lockout_threshold']} failed authentication "
            "attempts, providing insufficient protection against password "
            "guessing attacks."
        )

    # Policy controls
    if policy_evidence:

        finding = load_finding("password_policy", "PASS-001")

        weaknesses = "\n".join(
            f"- {evidence}"
            for evidence in policy_evidence
        )

        finding.commentary = (
            "The assessment identified the following weaknesses within the "
            "Active Directory password and account lockout policy:\n\n"
            f"{weaknesses}\n\n"
            + finding.commentary
        )

        findings.append(finding)

    write_markdown_report(
        findings,
        get_artefacts_dir() / "findings-passwords.md",
    )

#-------------------------------------------------------------------------------
# MACHINE ACCOUNT QUOTA
#-------------------------------------------------------------------------------

def run_maq_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute Machine Account Quota assessment checks.

    This check evaluates the Active Directory Machine Account Quota (MAQ) 
    configuration and determines whether authenticated users can create machine
    accounts within the domain.

    Findings are generated when machine account creation is permitted for 
    unprivileged users.
    """

    session_data = require_session()

    print_section("Machine Account Quota")

    if std_pass is None:
        std_pass = authenticate_standard_user()

    with progress("Checking Machine Account Quota..."):

        maq_results = maq_check(
            session_data["dc_ip"],
            session_data["standard_user"],
            std_pass,
        )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row(
        "Machine Account Quota",
        maq_results["machine_account_quota"],
    )

    table.add_row(
        "Delegated Group",
        maq_results["machine_join_group"],
    )

    table.add_row(
        "Machine Creation",
        (
            "[red]✗ Allowed[/red]"
            if maq_results["machine_created"]
            else "[green]✓ Denied[/green]"
        ),
    )

    if maq_results["cleanup_method"] == "Domain Admin Required":

        da_user, da_pass = authenticate_domain_admin()

        maq_results["machine_deleted"] = (
            cleanup_test_artifact(
                "maq-delete-machine-da",
                [
                    "nxc",
                    "smb",
                    session_data["dc_ip"],
                    "-u",
                    da_user,
                    "-p",
                    da_pass,
                    "-M",
                    "add-computer",
                    "-o",
                    f"NAME={maq_results['machine_name']}",
                    f"PASSWORD={maq_results['machine_password']}",
                    "DELETE=True",
                ],
            )
        )

        if maq_results["machine_deleted"]:

            maq_results["cleanup_method"] = "Domain Administrator"

        else:

            maq_results["cleanup_method"] = "Manual Intervention Required"

    table.add_row("Machine Cleanup", maq_results["cleanup_method"])

    console.print(table)

    generated_findings = []

    maq = int(maq_results["machine_account_quota"])

    if maq > 0:

        finding = load_finding("maq", "MAQ-001")

        finding.evidence.append(
            f"Machine Account Quota was configured as `{maq}`."
        )

        if maq_results["machine_created"]:

            finding.evidence.append(
                f"Authenticated user `{session_data['standard_user']}` "
                f"successfully created machine account "
                f"`{maq_results['machine_name']}$`."
            )

        if maq_results["machine_authenticated"]:

            finding.evidence.append(
                f"The created machine account `{maq_results['machine_name']}$` "
                "authenticated successfully."
            )

        if maq_results["machine_deleted"]:

            if maq_results["cleanup_method"] == "Domain Administrator":

                finding.evidence.append(
                    "The machine account was removed using a Domain "
                    "Administrator account."
                )

            else:

                finding.evidence.append(
                    "The machine account was successfully removed using the "
                    "creating account."
                )

        else:

            finding.evidence.append(
                "The machine account could not be removed following "
                "testing and requires manual remediation."
            )

        generated_findings.append(finding)

    write_markdown_report(
        generated_findings,
        get_artefacts_dir() / "findings-maq.md",
    )

#-------------------------------------------------------------------------------
# DNS RECORD CREATION
#-------------------------------------------------------------------------------

def run_dns_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute Active Directory-integrated DNS assessment checks.

    This check determines whether authenticated domain users can create DNS 
    records within Active Directory-integrated DNS zones.

    A temporary DNS record is created and removed to verify whether excessive 
    DNS permissions have been granted to standard users.

    Findings are generated when unauthorised DNS record creation is permitted.
    """

    session_data = require_session()

    print_section("DNS Record Creation")

    if std_pass is None:
        std_pass = authenticate_standard_user()

    with progress("Checking DNS permissions..."):

        dns_results, findings = (
            dns_record_creation_check(
                session_data["dc_ip"],
                session_data["domain"],
                session_data["standard_user"],
                std_pass,
            )
        )

    if dns_results["cleanup_method"] == "Domain Admin Required":

        da_user, da_pass = authenticate_domain_admin()

        dns_results["record_deleted"] = (
            cleanup_test_artifact(
                "dns-record-remove-da",
                [
                    "bloodyAD",
                    "-u", da_user,
                    "-p", da_pass,
                    "-d", session_data["domain"],
                    "--dc-ip", session_data["dc_ip"],
                    "remove",
                    "dnsRecord",
                    dns_results["record_name"].split(".")[0],
                    dns_results["record_ip"],
                ],
            )
        )

        if dns_results["record_deleted"]:

            dns_results["cleanup_method"] = "Domain Administrator"

            if findings:

                findings[0].evidence.append(
                    "The temporary DNS record was removed using a Domain "
                    "Administrator account."
                )

        else:

            dns_results["cleanup_method"] = "Manual Intervention Required"

            if findings:

                findings[0].evidence.append(
                    "The temporary DNS record could not be removed following "
                    "testing and requires manual remediation."
                )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row(
        "DNS Record Creation",
        (
            "[red]✗ Allowed[/red]"
            if dns_results["dns_record_creation"]
            else "[green]✓ Denied[/green]"
        ),
    )

    table.add_row("Record Cleanup", dns_results["cleanup_method"])

    console.print(table)

    write_markdown_report(
        findings,
        get_artefacts_dir() / "findings-dns.md",
    )

#-------------------------------------------------------------------------------
# PRE-WINDOWS 2000 COMPUTER ACCOUNTS
#-------------------------------------------------------------------------------

def run_pre2k_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute pre-Windows 2000 computer account assessment checks.

    This check identifies pre-created computer accounts susceptible to the 
    legacy pre-Windows 2000 machine account password convention.

    Findings are generated when Kerberos authentication can be achieved using
    predictable default machine account credentials.
    """

    session_data = require_session()

    print_section("Pre-Windows 2000 Computer Accounts")

    if std_pass is None:

        std_pass = (authenticate_standard_user())

    with progress("Checking pre-created computer accounts..."):

        pre2k_results, findings = (
            pre2k_check(
                session_data["dc_ip"],
                session_data["standard_user"],
                std_pass,
            )
        )

    table = Table()

    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row(
        "Accounts Identified",
        str(
            pre2k_results["accounts_found"]
        ),
    )

    table.add_row(
        "TGT Acquisition",
        (
            "[red]✗ Successful[/red]"
            if pre2k_results["tgt_obtained"]
            else "[green]✓ Denied[/green]"
        ),
    )

    console.print(table)

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-pre2k.md",
    )

#-------------------------------------------------------------------------------
# PRIVILEGED GROUP MEMBERSHIP
#-------------------------------------------------------------------------------

def run_privileged_group_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute privileged group membership assessment checks.

    This check evaluates membership of selected privileged Active Directory 
    groups and compares membership levels against the number of enabled user 
    accounts within the domain.

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

    table = Table()

    table.add_column("Group", style="cyan")
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
                if percentage >= 10.0
                else "[green]✓ Normal[/green]"
            ),
        )

    console.print(table)

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-privileged-groups.md",
    )

#-------------------------------------------------------------------------------
# DELEGATION
#-------------------------------------------------------------------------------

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

    table.add_row(
        "Unconstrained Delegation",
        str(len(delegation_results["unconstrained"])),
    )

    table.add_row(
        "Protocol Transition",
        str(len(delegation_results["protocol_transition"])),
    )

    console.print(table)

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-delegation.md",
    )

#-------------------------------------------------------------------------------
# KERBEROASTING
#-------------------------------------------------------------------------------

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

    table.add_row(
        "Kerberoastable Accounts",
        str(kerberoast_results["account_count"]),
    )

    console.print(table)

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-kerberoast.md",
    )

#-------------------------------------------------------------------------------
# ACTIVE DIRECTORY CERTIFICATE SERVICES
#-------------------------------------------------------------------------------

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

    for esc in SUPPORTED_ESC_CLASSES:

        count = len(adcs_results.get(esc, []))

        if count == 0:
            continue

        table.add_row(esc, str(count))

    console.print(table)

    print_info(
        "Findings are currently generated for ESC1, ESC8 and ESC15. Other "
        "identified ESC classifications are reported for visibility only."
    )

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-adcs.md",
    )

#-------------------------------------------------------------------------------
# LDAP INFORMATION EXPOSURE
#-------------------------------------------------------------------------------

def run_ldap_info_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute LDAP information exposure assessment checks.

    This check reviews commonly accessible LDAP attributes for potentially
    sensitive information, including account descriptions, informational
    fields, and password-related attributes.

    Findings are generated where sensitive information or password material is 
    identified within LDAP attributes.
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

    if sensitive_attributes:

        finding = load_finding("ldap_info", "LDAPINFO-001")

        for user, value, attribute in sensitive_attributes:

            finding.evidence.append(
                f"Account `{user}` contained potentially sensitive information "
                f"within the LDAP `{attribute}` attribute: `{value}`."
            )

        findings.append(finding)

    password_entries = (
        ldap_info_results["user_passwords"]
        + ldap_info_results["unix_passwords"]
    )

    if password_entries:

        finding = load_finding("ldap_info", "LDAPINFO-002")

        for entry in password_entries:

            finding.evidence.append(entry)

        findings.append(finding)

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-ldap-info.md",
    )

#-------------------------------------------------------------------------------
# AUTHENTICATION COERCION
#-------------------------------------------------------------------------------

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

    with progress("Reviewing coercion attack paths..."):

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

    table.add_row(
        "Coercible DCs",
        str(len(coercion_results["coercion_dcs"])),
    )

    table.add_row(
        "DCs with Print Spooler",
        str(len(coercion_results["spooler_dcs"])),
    )

    console.print(table)

    if coercion_results["coercion_dcs"]:

        finding = load_finding("coercion", "COERCE-001")

        for host, techniques in (coercion_results["coercion_dcs"].items()):

            finding.evidence.append(
                f"Domain Controller `{host}` exposed the following "
                "authentication coercion technique(s): "
                f"{', '.join(techniques)}."
            )

        findings.append(finding)

    if coercion_results["spooler_dcs"]:

        finding = load_finding("coercion", "COERCE-002")

        for dc in coercion_results["spooler_dcs"]:

            finding.evidence.append(
                f"Domain Controller `{dc}` had the Print Spooler service "
                "enabled."
            )

        findings.append(finding)

    write_markdown_report(
        findings,
        get_artefacts_dir()
        / "findings-coercion.md",
    )

#-------------------------------------------------------------------------------
# SELECTED MODULES
#-------------------------------------------------------------------------------

AVAILABLE_CHECKS = {
    "ldap": run_ldap_checks,
    "smb": run_smb_checks,
    "asreproast": run_asreproast_checks,
    "pass-pol": run_password_policy_checks,
    "maq": run_maq_checks,
    "dns": run_dns_checks,
    "pre2k": run_pre2k_checks,
    "privileged": run_privileged_group_checks,
    "delegation": run_delegation_checks,
    "kerberoast": run_kerberoast_checks,
    "adcs": run_adcs_checks,
    "local-admin": run_local_admin_checks,
    "ldap-info": run_ldap_info_checks,
    "coercion": run_coercion_checks,
}

def run_selected_checks(
    modules: list[str],
) -> None:
    """
    Execute a user-specified selection of assessment modules.

    This function allows individual assessment modules to be executed in any 
    combination rather than running the complete assessment. Where one or more 
    authenticated checks are selected, Standard User credentials are requested 
    once and reused for all applicable modules.

    Args:
        modules:
            Assessment modules to execute.
    """

    authenticated_modules = {
        "local-admin",
        "pass-pol",
        "maq",
        "dns",
        "pre2k",
        "privileged",
        "delegation",
        "kerberoast",
        "adcs",
        "ldap-info",
        "coercion",
    }

    requires_authentication = any(
        module in authenticated_modules
        for module in modules
    )

    std_pass = None

    if requires_authentication:

        std_pass = authenticate_standard_user()
        console.print()

    for module in modules:

        if module == "ldap":

            run_ldap_checks()

        elif module == "smb":
            run_smb_checks()

        elif module == "local-admin":
            run_local_admin_checks(std_pass)

        elif module == "pass-pol":
            run_password_policy_checks(std_pass)

        elif module == "maq":
            run_maq_checks(std_pass)

        elif module == "dns":
            run_dns_checks(std_pass)

        elif module == "pre2k":
            run_pre2k_checks(std_pass)

        elif module == "privileged":
            run_privileged_group_checks(std_pass)

        elif module == "delegation":
            run_delegation_checks(std_pass)

        elif module == "asreproast":
            run_asreproast_checks()

        elif module == "kerberoast":
            run_kerberoast_checks(std_pass)

        elif module == "adcs":
            run_adcs_checks(std_pass)

        elif module == "ldap-info":
            run_ldap_info_checks(std_pass)

        elif module == "coercion":
            run_coercion_checks(std_pass)

        else:
            print_error(f"Unknown module: {module}")

        console.print()

#-------------------------------------------------------------------------------
# MAIN FUNCTION
#-------------------------------------------------------------------------------

def run_checks() -> None:
    """
    Execute all assessment checks.

    This command performs both unauthenticated and authenticated security 
    checks against the target Active Directory environment.
    """

    # Unauthenticated checks
    run_ldap_checks()

    console.print()

    run_smb_checks()

    console.print()

    run_asreproast_checks()

    console.print()

    # Authenticated checks
    std_pass = authenticate_standard_user()

    console.print()

    run_local_admin_checks(std_pass)

    console.print()

    run_password_policy_checks(std_pass)

    console.print()

    run_maq_checks(std_pass)

    console.print()

    run_dns_checks(std_pass)

    console.print()

    run_pre2k_checks(std_pass)

    console.print()

    run_privileged_group_checks(std_pass)

    console.print()

    run_delegation_checks(std_pass)

    console.print()

    run_kerberoast_checks(std_pass)

    console.print()

    run_adcs_checks(std_pass)

    console.print()

    run_ldap_info_checks(std_pass)

    console.print()

    run_coercion_checks(std_pass)