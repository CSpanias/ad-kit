import typer
from rich.table import Table
from rich.text import Text

from ad_kit.checks.dns import dns_confirmation_excerpt, dns_record_creation_check
from ad_kit.checks.local_admin import local_admin_check
from ad_kit.checks.maq import maq_check
from ad_kit.checks.password_never_expires import password_never_expires_check
from ad_kit.checks.password_not_required import password_not_required_check
from ad_kit.checks.passwords import (
    UNKNOWN,
    FineGrainedPolicy,
    fine_grained_password_policies,
    password_policy_assessment,
    password_policy_check,
    resultant_password_policy,
    resultant_policy_name,
)
from ad_kit.checks.pre2k import pre2k_check
from ad_kit.core.checks import (
    capture_check_evidence,
    cleanup_test_artifact,
    format_check_evidence,
    warn_test_artifact_remaining,
)
from ad_kit.core.console import console, object_text, print_section
from ad_kit.core.exceptions import ADKitError, CheckExecutionError
from ad_kit.core.findings import (
    format_counted_commentary,
    load_finding,
    load_finding_definition,
)
from ad_kit.core.util import (
    count_form,
    count_text,
    progress,
    require_collected_data,
    require_session,
)
from ad_kit.reporting.results import record_findings, record_incomplete

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
    require_collected_data(
        session_data, "domain_computers_exported", "Domain computer"
    )

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
    table.add_column("Object", style="yellow")

    table.add_row(
        "Hosts",
        str(len(local_admin_results["hosts"])),
        object_text(local_admin_results["hosts"]),
    )

    table.add_row(
        "Domain Controllers",
        str(len(local_admin_results["domain_controllers"])),
        object_text(local_admin_results["domain_controllers"]),
    )

    console.print(table)

    findings = []

    if local_admin_results["hosts"]:

        finding = load_finding("local_admin", "LA-001")
        format_counted_commentary(finding, len(local_admin_results["hosts"]), "system", "systems")

        for host in local_admin_results["hosts"]:

            finding.evidence.append(
                f"Authenticated user `{session_data['standard_user']}` "
                f"was identified as a local administrator on `{host}`."
            )

        finding.evidence.append(
            f"A total of {count_text(len(local_admin_results['hosts']))} "
            f"{count_form(len(local_admin_results['hosts']), 'host', 'hosts')} permitted "
            "local administrator access."
        )

        findings.append(finding)

    if local_admin_results["domain_controllers"]:

        finding = load_finding("local_admin", "LA-002")
        controller_count = len(local_admin_results["domain_controllers"])
        format_counted_commentary(
            finding, controller_count, "Domain Controller (DC)", "Domain Controllers (DCs)"
        )

        for host in local_admin_results["domain_controllers"]:

            finding.evidence.append(
                f"Authenticated user `{session_data['standard_user']}` "
                "was identified as an administrator on DC "
                f"`{host}`."
            )

        finding.evidence.append(
            f"A total of {count_text(controller_count)} "
            f"{count_form(controller_count, 'DC', 'DCs')} "
            "permitted administrative access."
        )

        findings.append(finding)

    record_findings(findings)

def run_password_policy_checks(
    std_pass: str | None = None,
) -> None:
    """
    Execute password policy assessment checks.

    This check authenticates using a valid domain account and retrieves the
    default domain password policy. Configuration settings are assessed
    against common Active Directory security practices and the results are 
    displayed in tabular format.

    Assessed settings include password length, password history, complexity
    requirements, account lockout configuration, and minimum password age.
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

    settings = (
        ("Minimum Length", "minimum_length"),
        ("Password History", "password_history"),
        ("Minimum Age", "minimum_age"),
        ("Complexity", "complexity"),
        ("Observation Window", "observation_window"),
        ("Lockout Threshold", "lockout_threshold"),
        ("Lockout Duration", "lockout_duration"),
    )
    for label, key in settings:
        table.add_row(label, password_policy[key], assessment[key])

    console.print(table)

    fine_grained: list[FineGrainedPolicy] = []
    fgpp_incomplete = None
    fgpp_skipped = False
    resultant_checked = False
    resultant_dn = None
    resultant_pso: FineGrainedPolicy | None = None
    if typer.confirm(
        "Assess fine-grained password policies using Domain Administrator credentials?",
        default=False,
    ):
        da_user, da_pass = authenticate_domain_admin()
        try:
            with progress("Retrieving fine-grained password policies..."):
                fine_grained, fgpp_incomplete = fine_grained_password_policies(
                    session_data["dc_ip"], da_user, da_pass
                )
        except CheckExecutionError as exc:
            fgpp_incomplete = str(exc)
        try:
            with progress("Checking the Standard User's effective password policy..."):
                resultant_dn = resultant_password_policy(
                    session_data["dc_ip"], da_user, da_pass, session_data["standard_user"]
                )
            resultant_checked = True
            if resultant_dn:
                name = resultant_policy_name(
                    session_data["dc_ip"], da_user, da_pass, resultant_dn
                )
                matches = [pso for pso in fine_grained if pso.name.casefold() == name.casefold()]
                if len(matches) != 1:
                    raise CheckExecutionError(
                        "password-policy-resultant", [],
                        stderr="The resultant policy settings could not be uniquely matched "
                        "to the enumerated fine-grained policies.",
                    )
                resultant_pso = matches[0]
        except CheckExecutionError as exc:
            record_incomplete("pass-pol", session_data["dc_ip"], str(exc))
    else:
        fgpp_skipped = True
        record_incomplete(
            "pass-pol", session_data["dc_ip"],
            "Fine-grained password policies were not assessed.",
            notify=False,
        )

    if fgpp_incomplete:
        record_incomplete("pass-pol", session_data["dc_ip"], fgpp_incomplete)

    if not fgpp_skipped:
        if not resultant_checked:
            message = "Standard User effective password policy: Unknown"
        elif not resultant_dn:
            message = "Standard User effective password policy: Default domain policy presumed"
        elif resultant_pso:
            message = f"Standard User effective password policy: {resultant_pso.name}"
        else:
            message = f"Standard User resultant policy: {resultant_dn} (settings not matched)"
        console.print(Text(message))

    if fine_grained:
        for pso in fine_grained:
            pso_assessment = password_policy_assessment(pso.settings)
            unknown_pso = [
                setting.replace("_", " ") for setting, status in pso_assessment.items()
                if status == UNKNOWN
            ]
            if unknown_pso:
                record_incomplete(
                    "pass-pol", session_data["dc_ip"],
                    f"Could not assess settings in fine-grained policy {pso.name}: "
                    + ", ".join(unknown_pso) + ". See password-policy-fine-grained.txt evidence.",
                )
            pso_table = Table(title=Text(f"Fine-Grained Password Policy: {pso.name}"))
            pso_table.add_column("Setting", style="cyan")
            pso_table.add_column("Value", style="green")
            pso_table.add_column("Assessment", style="yellow")
            for label, key in (*settings, ("Reversible Encryption", "reversible_encryption")):
                status = pso_assessment[key]
                if key == "minimum_age" and pso.settings[key].lower() == "0 days":
                    status = "[red]✗ Too Short[/red]"
                pso_table.add_row(label, pso.settings[key], status)
            pso_table.add_row(
                "Applies To",
                object_text(pso.applies_to) if pso.applies_to else "Not reported",
                "",
            )
            pso_table.add_row("Precedence", pso.precedence or "Unknown", "")
            console.print(pso_table)

    unknown = [
        setting.replace("_", " ")
        for setting, status in assessment.items()
        if status == UNKNOWN
    ]
    if unknown:
        details = password_policy.get("lockout_duration_error")
        record_incomplete(
            "pass-pol",
            session_data["dc_ip"],
            "Could not assess: " + ", ".join(unknown)
            + ". See password-policy.txt evidence."
            + (f" Lockout duration lookup: {details}." if details else ""),
        )

    weak_settings = [
        setting for setting, status in assessment.items()
        if status.startswith("[red]")
    ]
    if not weak_settings and not any(
        status.startswith("[red]")
        for pso in fine_grained
        if pso.applies_to or pso is resultant_pso
        for status in password_policy_assessment(pso.settings).values()
    ):
        return

    finding = load_finding("password_policy", "PASS-001")
    definitions = load_finding_definition("password_policy", "PASS-001")["settings"]
    remediation: list[str] = []
    references: list[str] = []

    def prose_value(value: str) -> str:
        tokens = value.split()
        formatted = []
        for index, token in enumerate(tokens):
            if token.isdecimal() and 1 <= int(token) <= 9:
                token = count_text(int(token))
            elif (
                index and tokens[index - 1].isdecimal()
                and token.lower() in {"days", "hours", "minutes"}
            ):
                token = count_form(int(tokens[index - 1]), token[:-1], token)
            formatted.append(token)
        return " ".join(formatted)

    def describe_setting(
        setting: str, values: dict[str, str], *, fine_grained: bool = False
    ) -> str:
        definition_key = (
            "lockout_disabled"
            if setting == "lockout_threshold" and int(values[setting]) == 0
            else setting
        )
        content = definitions[definition_key]
        value = values[setting]
        format_values = {
            "value": "zero days" if setting == "minimum_age" and value.lower() == "none"
            else prose_value(value)
        }
        if setting == "minimum_length":
            format_values["character_word"] = count_form(int(value), "character", "characters")
        elif setting == "password_history":
            format_values["password_word"] = count_form(int(value), "password", "passwords")
        remediation.append("- " + content["remediation"])
        references.extend(content["references"])
        if fine_grained and setting == "minimum_age" and value.lower() == "0 days":
            return (
                "- The minimum password age was less than one day, "
                "which may allow rapid password cycling to bypass password history."
            )
        if fine_grained and setting == "observation_window" and value.lower() == "0 minutes":
            return (
                "- The lockout observation window was less than one minute, "
                "which may allow failed attempts to be reset quickly."
            )
        return "- " + content["commentary"].format(**format_values)

    commentary = [finding.commentary.strip()]
    if weak_settings:
        commentary.append(
            "The default domain policy contained the following "
            + count_form(len(weak_settings), "setting", "settings")
            + " that may not align with common security practices:\n\n"
            + "\n".join(describe_setting(setting, password_policy) for setting in weak_settings)
        )

    if resultant_checked:
        user = session_data["standard_user"].replace("`", "\\`")
        if not resultant_dn:
            detail = (
                f"No fine-grained password policy was returned for testing account `{user}`; "
                "the default domain policy is presumed to apply."
            )
            if any(pso.applies_to for pso in fine_grained):
                detail += (
                    " If a fine-grained policy is expected for this account, the absence of "
                    "a resultant policy warrants investigation."
                )
            commentary.append(detail)
        elif resultant_pso:
            name = resultant_pso.name.replace("`", "\\`")
            commentary.append(
                f"Fine-grained password policy `{name}` was the resultant policy for "
                f"testing account `{user}`."
            )
        else:
            dn = resultant_dn.replace("`", "\\`")
            commentary.append(
                f"Testing account `{user}` had resultant fine-grained policy `{dn}`, "
                "but its settings could not be matched to the assessed policies."
            )

    for pso in fine_grained:
        pso_assessment = password_policy_assessment(pso.settings)
        pso_weak = [
            setting for setting, status in pso_assessment.items()
            if status.startswith("[red]")
        ]
        name = pso.name.replace("`", "\\`")
        if pso.applies_to:
            assignment = ", ".join(
                f"`{entry.replace('`', chr(92) + '`')}`" for entry in pso.applies_to
            )
            details = (
                f"Fine-grained password policy `{name}` was reported as applying to {assignment}."
            )
        else:
            details = f"No assigned users or groups were reported for fine-grained policy `{name}`."
        improvements = [
            setting for setting in weak_settings
            if pso_assessment[setting].startswith("[green]")
        ]
        if not pso.applies_to and pso is not resultant_pso:
            details += " The policy was therefore not identified as applying to standard users"
            if weak_settings:
                details += (
                    " and cannot be considered to address the identified default-policy "
                    + count_form(len(weak_settings), "weakness", "weaknesses")
                )
            details += "."
        elif improvements:
            values = ", ".join(
                f"{setting.replace('_', ' ')}: "
                + ("at least " if setting == "minimum_age" else "")
                + prose_value(pso.settings[setting])
                for setting in improvements
            )
            details += (
                f" Unlike the default policy, the following settings met the assessment "
                f"baseline: {values}. For accounts for which this is the effective policy, "
                "these settings address the corresponding default-policy weaknesses."
            )
        elif weak_settings:
            details += (
                " The assessed settings did not confirm that this policy addresses any of "
                "the identified default-policy weaknesses."
            )
        if (pso.applies_to or pso is resultant_pso) and pso_weak:
            details += (
                " The policy contained the following "
                + count_form(len(pso_weak), "setting", "settings")
                + " that may not align with common security practices:\n\n"
                + "\n".join(
                    describe_setting(setting, pso.settings, fine_grained=True)
                    for setting in pso_weak
                )
            )
        commentary.append(details)

    notes = []
    if fine_grained:
        notes.append(
            "Policy assignments do not establish the effective policy for every "
            "account. Direct assignments, group membership, and policy precedence can affect "
            "which policy applies; verify the resultant policy for affected accounts."
        )
        references.append(
            "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/"
            "get-started/adac/fine-grained-password-policies"
        )
    if fgpp_incomplete or fgpp_skipped:
        notes.append(
            "Fine-grained password policies were not fully assessed, so effective "
            "settings for individual accounts may differ from the default domain policy."
        )
    if not fgpp_skipped and not resultant_checked:
        notes.append(
            "The resultant password policy for the testing account could not be determined."
        )

    finding.commentary = "\n\n".join(commentary)
    finding.commentary_note = " ".join(notes)
    remediation_intro = (
        "Review the affected default or fine-grained password policies against "
        "organisational requirements and the controls in place:"
        if fine_grained else finding.remediation.strip()
    )
    validation = (
        "Test proposed changes, verify the resultant policy for affected accounts, "
        "and communicate changes to users and service owners."
        if fine_grained else
        "Test proposed changes and communicate them to affected users and service owners."
    )
    finding.remediation = (
        remediation_intro + "\n\n" + "\n".join(dict.fromkeys(remediation))
        + "\n\n" + validation
    )
    finding.references = list(dict.fromkeys(references))
    record_findings([finding])

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

    record_findings(findings)

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

    record_findings(findings)

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

    with capture_check_evidence() as evidence, progress("Checking Machine Account Quota..."):

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

        try:
            da_user, da_pass = authenticate_domain_admin()

            with capture_check_evidence() as cleanup_evidence:
                maq_results["machine_deleted"] = cleanup_test_artifact(
                    "maq-delete-machine-da",
                    [
                        "nxc", "ldap", session_data["dc_ip"],
                        "-u", da_user,
                        "-p", da_pass,
                        "-M", "add-computer",
                        "-o",
                        f"NAME={maq_results['machine_name']}",
                        f"PASSWORD={maq_results['machine_password']}",
                        "DELETE=True",
                    ],
                )
            evidence.extend(cleanup_evidence)
        except (ADKitError, KeyboardInterrupt):
            warn_test_artifact_remaining(
                "machine account", f"{maq_results['machine_name']}$",
                "maq-create-machine",
            )
            raise

        if maq_results["machine_deleted"]:

            maq_results["cleanup_method"] = "Domain Administrator"

        else:

            maq_results["cleanup_method"] = "Manual Intervention Required"
            warn_test_artifact_remaining(
                "machine account", f"{maq_results['machine_name']}$",
                "maq-create-machine",
            )

    table.add_row("Machine Cleanup", maq_results["cleanup_method"])

    console.print(table)
    generated_findings = []

    maq = int(maq_results["machine_account_quota"])

    if maq > 0:

        finding = load_finding("maq", "MAQ-001")
        finding.evidence_in_commentary = True

        finding.evidence.append(
            f"MAQ was configured as `{maq}`."
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

    if generated_findings and evidence:
        print_section("Machine Account Quota - Command Evidence")
        for record in evidence:
            console.print(format_check_evidence(record), markup=False, highlight=False)
            console.print()

    record_findings(generated_findings)

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

    with capture_check_evidence() as evidence, progress("Checking DNS permissions..."):

        dns_results, findings = (
            dns_record_creation_check(
                session_data["dc_ip"],
                session_data["domain"],
                session_data["standard_user"],
                std_pass,
            )
        )

    if dns_results["cleanup_method"] == "Domain Admin Required":

        try:
            da_user, da_pass = authenticate_domain_admin()

            with capture_check_evidence() as cleanup_evidence:
                dns_results["record_deleted"] = cleanup_test_artifact(
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
            evidence.extend(cleanup_evidence)
        except (ADKitError, KeyboardInterrupt):
            warn_test_artifact_remaining(
                "DNS record", dns_results["record_name"], "dns-record-create"
            )
            raise

        if dns_results["record_deleted"]:

            dns_results["cleanup_method"] = "Domain Administrator"

            if findings:

                findings[0].evidence.append(
                    "The temporary DNS record was removed using a Domain "
                    "Administrator account."
                )

        else:

            dns_results["cleanup_method"] = "Manual Intervention Required"
            warn_test_artifact_remaining(
                "DNS record", dns_results["record_name"], "dns-record-create"
            )

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
    if findings and evidence:
        print_section("DNS Record Creation - Command Evidence")
        for record in evidence:
            excerpt = None
            if record.name == "dns-record-confirm":
                excerpt, _ = dns_confirmation_excerpt(
                    record.stdout, dns_results["record_name"], dns_results["record_ip"]
                )
                excerpt = (
                    f"[Filtered DNS dump for {dns_results['record_name']}]\n"
                    + (excerpt or "No matching record returned.")
                )
            console.print(format_check_evidence(record, excerpt), markup=False, highlight=False)
            console.print()

    record_findings(findings)

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

    if findings and pre2k_results["accounts"]:
        accounts = Table(title="Identified Pre-Created Accounts")
        accounts.add_column("Object", style="cyan")
        for account in pre2k_results["accounts"]:
            accounts.add_row(object_text([account]))
        console.print()
        console.print(accounts)

    record_findings(findings)
