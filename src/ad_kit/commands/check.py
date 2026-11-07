"""
Assessment checks.
"""

import typer

from rich.table import Table

from ad_kit.core.checks import (
    load_domain_computers,
    load_dc_hostnames,
    validate_credentials
)
from ad_kit.checks.ldap import ldap_check
from ad_kit.checks.passwords import (
    password_policy_check, 
    password_policy_assessment
)
from ad_kit.checks.smb import smb_configuration_check
from ad_kit.core.console import (
    console, 
    print_section, 
    print_error, 
    print_success
)
from ad_kit.core.findings import load_finding
from ad_kit.core.util import (
    progress, 
    load_session, 
    get_artefacts_dir, 
    print_info
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

    session_data = load_session()

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
# AUTHENTICATED CHECKS
#-------------------------------------------------------------------------------

def authenticate_standard_user() -> str:
    """
    Prompt for and validate Standard User credentials.

    The user is prompted to enter the password for the
    Standard User account stored in the assessment
    session. Authentication is validated against the
    target domain before authenticated checks are
    executed.

    Returns:
        The validated Standard User password.

    Raises:
        RuntimeError:
            If authentication cannot be completed.
    """

    session_data = load_session()

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

#-------------------------------------------------------------------------------
# PASSWORD POLICY
#-------------------------------------------------------------------------------

def run_password_policy_checks() -> None:
    """
    Execute password policy assessment checks.

    This check authenticates using a valid domain
    account and retrieves the effective domain password
    policy. Configuration settings are assessed against
    common Active Directory security practices and the
    results are displayed in tabular format.

    Assessed settings include password length, password
    history, complexity requirements, account lockout
    configuration, and password age settings.
    """

    session_data = load_session()

    print_section("Password Policy")

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

    password_policy_issues = []
    lockout_policy_issues = []

    password_policy_evidence = []
    lockout_policy_evidence = []

    # Determine failed password policy settings
    for setting in (
        "minimum_length",
        "password_history",
        "minimum_age",
        "maximum_age",
        "complexity",
    ):

        if assessment[setting] != "[green]✓ OK[/green]":
            password_policy_issues.append(setting)

    # Determine failed lockout settings
    for setting in (
        "observation_window",
        "lockout_duration",
        "lockout_threshold",
    ):

        if assessment[setting] != "[green]✓ OK[/green]":
            lockout_policy_issues.append(setting)

    # Build password policy evidence
    if assessment["minimum_length"] != "[green]✓ OK[/green]":

        password_policy_evidence.append(
            (
                "Minimum password length was configured as "
                f"{password_policy['minimum_length']} characters, which is "
                "below the recommended best practice."
            )
        )

    if assessment["password_history"] != "[green]✓ OK[/green]":

        password_policy_evidence.append(
            (
                "Password history retained only "
                f"{password_policy['password_history']} previous "
                "password(s), increasing the likelihood of password reuse."
            )
        )

    if assessment["minimum_age"] != "[green]✓ OK[/green]":

        password_policy_evidence.append(
            (
                "Minimum password age was not configured, allowing users to "
                "rapidly change passwords and potentially circumvent "
                "password history controls."
            )
        )

    if assessment["maximum_age"] != "[green]✓ OK[/green]":

        password_policy_evidence.append(
            (
                "Maximum password age was not configured, resulting in "
                "passwords that may remain unchanged indefinitely."
            )
        )

    if assessment["complexity"] != "[green]✓ OK[/green]":

        password_policy_evidence.append(
            (
                "Password complexity requirements were disabled, allowing "
                "weak or easily guessable passwords to be configured."
            )
        )

    # Build lockout policy evidence
    if assessment["observation_window"] != "[green]✓ OK[/green]":

        lockout_policy_evidence.append(
            (
                "The account lockout observation window was configured "
                f"as {password_policy['observation_window']}."
            )
        )

    if assessment["lockout_duration"] != "[green]✓ OK[/green]":

        lockout_policy_evidence.append(
            (
                "The account lockout duration was configured as "
                f"{password_policy['lockout_duration']}."
            )
        )

    if assessment["lockout_threshold"] != "[green]✓ OK[/green]":

        lockout_policy_evidence.append(
            (
                "The account lockout threshold was configured as "
                f"{password_policy['lockout_threshold']} failed "
                "authentication attempts, providing insufficient "
                "protection against password guessing attacks."
            )
        )

    # Policy controls
    if password_policy_issues:

        finding = load_finding("passwords", "PASS-001")
        finding.evidence.extend(password_policy_evidence)
        findings.append(finding)

    # Lockout controls
    if lockout_policy_issues:

        finding = load_finding("passwords", "PASS-002")
        finding.evidence.extend(lockout_policy_evidence)
        findings.append(finding)  

    write_markdown_report(
        findings,
        get_artefacts_dir() / "findings-passwords.md",
    )  

#-------------------------------------------------------------------------------
# MAIN FUNCTION
#-------------------------------------------------------------------------------

def run_checks() -> None:
    """
    Execute all assessment checks.

    This command performs both unauthenticated and
    authenticated security checks against the target
    Active Directory environment.
    """

    # Unauthenticated checks
    run_ldap_checks()

    console.print()

    run_smb_checks()

    console.print()

    # Authenticated checks
    run_password_policy_checks()
