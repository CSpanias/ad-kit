from rich.table import Table

from ad_kit.checks.dns import dns_record_creation_check
from ad_kit.checks.local_admin import local_admin_check
from ad_kit.checks.maq import maq_check
from ad_kit.checks.password_never_expires import password_never_expires_check
from ad_kit.checks.password_not_required import password_not_required_check
from ad_kit.checks.passwords import (
    password_policy_assessment,
    password_policy_check,
)
from ad_kit.checks.pre2k import pre2k_check
from ad_kit.core.checks import cleanup_test_artifact
from ad_kit.core.console import console, print_section
from ad_kit.core.findings import load_finding
from ad_kit.core.util import get_artefacts_dir, progress, require_session
from ad_kit.reporting.results import record_findings

from .credentials import authenticate_domain_admin, authenticate_standard_user


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

    record_findings(
        findings,
        get_artefacts_dir()
        / "findings-local-admin.md",
    )

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

    record_findings(
        findings,
        get_artefacts_dir() / "findings-passwords.md",
    )

def run_password_not_required_checks(
    std_pass: str | None = None,
) -> None:
    """
    Identify enabled accounts with the PASSWD_NOTREQD flag set.

    The check reviews enabled accounts separately from the domain password
    policy configuration check.
    """

    session_data = require_session()

    print_section("Password Not Required Accounts")

    if std_pass is None:
        std_pass = authenticate_standard_user()

    with progress("Checking accounts with PASSWD_NOTREQD..."):
        results, findings = password_not_required_check(
            session_data["dc_ip"],
            session_data["standard_user"],
            std_pass,
        )

    table = Table()
    table.add_column("Enabled Account", style="cyan")
    table.add_column("Status", style="yellow")

    if results["accounts"]:
        for account in results["accounts"]:
            table.add_row(account, "PASSWD_NOTREQD set")
    else:
        table.add_row("None found", "[green]✓ OK[/green]")

    console.print(table)

    record_findings(
        findings,
        get_artefacts_dir() / "findings-password-not-required.md",
    )

def run_password_never_expires_checks(
    std_pass: str | None = None,
) -> None:
    """
    Identify enabled accounts configured with non-expiring passwords.
    """

    session_data = require_session()

    print_section("Password Never Expires Accounts")

    if std_pass is None:
        std_pass = authenticate_standard_user()

    with progress("Checking accounts with non-expiring passwords..."):
        results, findings = password_never_expires_check(
            session_data["dc_ip"],
            session_data["standard_user"],
            std_pass,
        )

    table = Table()
    table.add_column("Enabled Account", style="cyan")
    table.add_column("Status", style="yellow")

    if results["accounts"]:
        for account in results["accounts"]:
            table.add_row(account, "Password never expires")
    else:
        table.add_row("None found", "[green]✓ OK[/green]")

    console.print(table)

    record_findings(
        findings,
        get_artefacts_dir() / "findings-password-never-expires.md",
    )

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

    maq_value = maq_results["machine_account_quota"]
    maq_color = (
        "red"
        if str(maq_value).isdecimal() and int(maq_value) > 0
        else "green"
    )

    table.add_row(
        "Machine Account Quota",
        f"[{maq_color}]{maq_value}[/{maq_color}]",
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
                    "nxc", "smb", session_data["dc_ip"],
                    "-u", da_user,
                    "-p", da_pass,
                    "-M", "add-computer",
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

    record_findings(
        generated_findings,
        get_artefacts_dir() / "findings-maq.md",
    )

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

    record_findings(
        findings,
        get_artefacts_dir() / "findings-dns.md",
    )

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

    record_findings(
        findings,
        get_artefacts_dir()
        / "findings-pre2k.md",
    )
