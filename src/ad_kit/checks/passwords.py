"""
Password-related assessment checks.
"""

import re
from dataclasses import dataclass, field

from ad_kit.core.checks import (
    ANSI_ESCAPE_PATTERN,
    PASSWORD_POLICY_BASELINE,
    duration_to_minutes,
    run_check,
)
from ad_kit.core.exceptions import CheckExecutionError

UNKNOWN = "[yellow]⚠ Unknown[/yellow]"
MANUAL_UNLOCK = "Until manually unlocked"
MANUAL_UNLOCK_LDAP = "-9223372036854775808"


@dataclass
class FineGrainedPolicy:
    name: str
    settings: dict[str, str] = field(default_factory=dict)
    applies_to: list[str] = field(default_factory=list)
    precedence: str = ""
    assignments_seen: bool = False


def _query_entries(output: str, evidence: str) -> list[tuple[str, dict[str, list[str]]]]:
    entries: list[tuple[str, dict[str, list[str]]]] = []
    current: dict[str, list[str]] | None = None
    for line in ANSI_ESCAPE_PATTERN.sub("", output).splitlines():
        match = re.match(r"^\s*LDAPS?\s+\S+\s+\d+\s+\S+\s*(.*)$", line, re.I)
        if not match:
            continue
        text = match.group(1).strip()
        if text.startswith(("[-]", "[!]")):
            raise CheckExecutionError(
                evidence, [], stderr=f"LDAP query failed; see {evidence}.txt."
            )
        header = re.match(r"^\[\+\]\s+Response for object:\s*(.+)$", text, re.I)
        if header:
            current = {}
            entries.append((header.group(1).strip(), current))
        elif current is not None:
            attribute = re.match(r"^([a-z][a-z0-9-]*)\s+(.+)$", text, re.I)
            if attribute:
                current.setdefault(attribute.group(1).casefold(), []).append(
                    attribute.group(2).strip()
                )
            elif re.match(
                r"^(sAMAccountName|userPrincipalName|msDS-ResultantPSO|name)\b", text, re.I
            ):
                raise CheckExecutionError(
                    evidence, [], stderr=f"LDAP returned an empty attribute; see {evidence}.txt."
                )
    return entries


def _escape_ldap_filter(value: str) -> str:
    replacements = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\x00": r"\00"}
    return "".join(replacements.get(char, char) for char in value)


def resultant_password_policy(
    dc_ip: str, admin: str, password: str, standard_user: str,
) -> str | None:
    """Return the resultant PSO DN, or None when a verified user has no reported PSO."""
    evidence = "password-policy-resultant"
    account = standard_user.rsplit("\\", 1)[-1]
    attribute = "userPrincipalName" if "@" in account else "sAMAccountName"
    query = f"(&(objectClass=user)({attribute}={_escape_ldap_filter(account)}))"
    output = run_check(
        evidence,
        ["nxc", "ldap", dc_ip, "-u", admin, "-p", password, "--query", query,
         "sAMAccountName userPrincipalName msDS-ResultantPSO"],
        sensitive_values=[password], show_progress=False,
    )
    entries = _query_entries(output, evidence)
    if len(entries) != 1 or [
        value.casefold() for value in entries[0][1].get(attribute.casefold(), [])
    ] != [account.casefold()]:
        raise CheckExecutionError(
            evidence, [], stderr=f"Could not identify the testing account; see {evidence}.txt."
        )
    values = entries[0][1].get("msds-resultantpso", [])
    if len(values) > 1:
        raise CheckExecutionError(
            evidence, [], stderr=f"Multiple resultant policies were returned; see {evidence}.txt."
        )
    return values[0] if values else None


def resultant_policy_name(
    dc_ip: str, admin: str, password: str, policy_dn: str,
) -> str:
    """Identify a resultant PSO by its full DN and require its name to be unique."""
    evidence = "password-policy-resultant-pso"
    output = run_check(
        evidence,
        ["nxc", "ldap", dc_ip, "-u", admin, "-p", password, "--query",
         "(objectClass=msDS-PasswordSettings)", "name"],
        sensitive_values=[password], show_progress=False,
    )
    entries = _query_entries(output, evidence)
    matches = [attrs["name"][0] for dn, attrs in entries
               if dn.casefold() == policy_dn.casefold() and len(attrs.get("name", [])) == 1]
    if len(matches) != 1 or sum(
        1 for _, attrs in entries
        for name in attrs.get("name", []) if name.casefold() == matches[0].casefold()
    ) != 1:
        raise CheckExecutionError(
            evidence, [],
            stderr=f"Could not uniquely identify the resultant policy; see {evidence}.txt.",
        )
    return matches[0]


def fine_grained_password_policies(
    dc_ip: str, username: str, password: str
) -> tuple[list[FineGrainedPolicy], str | None]:
    """Read NetExec's PSO output; an absent count cannot establish an empty result."""
    output = run_check(
        "password-policy-fine-grained",
        ["nxc", "ldap", dc_ip, "-u", username, "-p", password, "--pso"],
        sensitive_values=[password],
        show_progress=False,
    )
    labels = {
        "minimum password length": "minimum_length",
        "minimum password history length": "password_history",
        "minimum password age": "minimum_age",
        "complexity enabled": "complexity",
        "reversible encryption": "reversible_encryption",
        "observation window": "observation_window",
        "lockout threshold": "lockout_threshold",
        "lockout duration": "lockout_duration",
    }
    policies: list[FineGrainedPolicy] = []
    current: FineGrainedPolicy | None = None
    in_assignments = False
    reported_count: int | None = None
    has_error = False
    for line in ANSI_ESCAPE_PATTERN.sub("", output).splitlines():
        match = re.match(r"^\s*LDAPS?\s+\S+\s+\d+\s+\S+\s*(.*)$", line, re.I)
        if not match:
            continue
        text = match.group(1).strip()
        count = re.fullmatch(r"(\d+)\s+PSO Objects? found!", text, re.I)
        if count:
            reported_count = int(count.group(1))
        if text.startswith("[-]"):
            has_error = True
        key, separator, value = text.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "policy name" and separator:
            current = FineGrainedPolicy(name=value)
            policies.append(current)
            in_assignments = False
        elif current is not None and key == "policy applies to" and separator:
            in_assignments = True
            current.assignments_seen = True
            if value:
                current.applies_to.append(value)
        elif current is not None and in_assignments and re.match(r"^CN=", text, re.I):
            current.applies_to.append(text)
        elif current is not None and key in labels and separator:
            in_assignments = False
            if key in {"complexity enabled", "reversible encryption"}:
                value = {"true": "Enabled", "false": "Disabled"}.get(value.lower(), UNKNOWN)
            current.settings[labels[key]] = value
        elif current is not None and key == "precedence" and separator:
            in_assignments = False
            current.precedence = value.partition(" ")[0]

    for policy in policies:
        for setting in labels.values():
            policy.settings.setdefault(setting, UNKNOWN)
        if re.fullmatch(r"0\s+minutes?", policy.settings["lockout_duration"], re.I):
            policy.settings["lockout_duration"] = UNKNOWN
    if (
        reported_count is None or reported_count != len(policies) or has_error
        or any(
            not policy.name or not policy.assignments_seen or not policy.precedence.isdecimal()
            for policy in policies
        )
    ):
        return [policy for policy in policies if policy.name], (
            "Fine-grained policy enumeration was incomplete or could not be verified; "
            "see password-policy-fine-grained.txt evidence"
        )
    return policies, None


def password_policy_check(
    dc_ip: str,
    username: str,
    password: str,
) -> dict:
    """
    Retrieve and parse the domain password policy.

    Args:
        dc_ip: Domain Controller IP address.
        username: LDAP username.
        password: LDAP password.

    Returns:
        Dictionary containing password policy
        settings.
    """

    output = run_check(
        "password-policy",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "--pass-pol",
        ],
    )

    minimum_length = UNKNOWN
    password_history = UNKNOWN
    minimum_age = UNKNOWN
    complexity = UNKNOWN
    observation_window = UNKNOWN
    lockout_duration = UNKNOWN
    lockout_threshold = UNKNOWN

    for line in output.splitlines():

        line = line.strip()

        if "Minimum password length:" in line:
            minimum_length = (line.split(":")[-1].strip())

        elif "Password history length:" in line:
            password_history = (line.split(":")[-1].strip())

        elif "Minimum password age:" in line:
            minimum_age = (line.split(":", 1)[1].strip())

        elif "Domain Password Complex:" in line:
            value = (line.split(":")[-1].strip())
            complexity = {"1": "Enabled", "0": "Disabled"}.get(value, UNKNOWN)

        elif "Reset Account Lockout Counter:" in line:
            observation_window = (line.split(":", 1)[1].strip())

        elif "Locked Account Duration:" in line:
            lockout_duration = (line.split(":", 1)[1].strip())

        elif "Account Lockout Threshold:" in line:
            lockout_threshold = (line.split(":")[-1].strip())

    result = {
        "minimum_length": minimum_length,
        "password_history": password_history,
        "minimum_age": minimum_age,
        "complexity": complexity,
        "observation_window": observation_window,
        "lockout_duration": lockout_duration,
        "lockout_threshold": lockout_threshold,
    }

    if lockout_duration.lower() == "not set" and not (
        lockout_threshold.isdecimal() and int(lockout_threshold) == 0
    ):
        try:
            raw_output = run_check(
                "password-policy-lockout-duration",
                [
                    "nxc", "ldap", dc_ip, "-u", username, "-p", password,
                    "--query", "(objectClass=domainDNS)", "lockoutDuration",
                ],
            )
        except CheckExecutionError as exc:
            result["lockout_duration"] = UNKNOWN
            result["lockout_duration_error"] = str(exc)
        else:
            objects = re.findall(r"\bResponse for object:", raw_output, re.IGNORECASE)
            values = re.findall(
                r"\blockoutDuration[ \t]+(-?\d+)[ \t]*\r?$",
                raw_output,
                re.IGNORECASE | re.MULTILINE,
            )
            if len(objects) == 1 and values == [MANUAL_UNLOCK_LDAP]:
                result["lockout_duration"] = MANUAL_UNLOCK
            else:
                result["lockout_duration"] = UNKNOWN
                result["lockout_duration_error"] = (
                    "LDAP query did not return a single documented manual-unlock value; "
                    "see password-policy-lockout-duration.txt evidence"
                )

    return result


def password_policy_assessment(
    policy: dict,
) -> dict[str, str]:
    """
    Assess the password policy against
    the AD-Kit baseline.
    """

    assessment = {}

    #---------------------------------------------------------------------------
    # MINIMUM LENGTH
    #---------------------------------------------------------------------------

    if not policy["minimum_length"].isdecimal():
        assessment["minimum_length"] = UNKNOWN
    elif int(policy["minimum_length"]) < PASSWORD_POLICY_BASELINE["minimum_length"]:
        assessment["minimum_length"] = "[red]✗ Too Short[/red]"
    else:
        assessment["minimum_length"] = "[green]✓ OK[/green]"

    #---------------------------------------------------------------------------
    # PASSWORD HISTORY
    #---------------------------------------------------------------------------

    if not policy["password_history"].isdecimal():
        assessment["password_history"] = UNKNOWN
    elif int(policy["password_history"]) < PASSWORD_POLICY_BASELINE["password_history"]:
        assessment["password_history"] = "[red]✗ Too Low[/red]"
    else:
        assessment["password_history"] = "[green]✓ OK[/green]"

    #---------------------------------------------------------------------------
    # MINIMUM AGE
    #---------------------------------------------------------------------------
    
    minimum_age = policy["minimum_age"].lower()

    minimum_age_minutes = duration_to_minutes(minimum_age)
    if minimum_age in {"none", "not set"} or minimum_age_minutes == 0:
        assessment["minimum_age"] = "[red]✗ Not Set[/red]"
    elif minimum_age_minutes is None:
        assessment["minimum_age"] = UNKNOWN
    elif minimum_age_minutes < PASSWORD_POLICY_BASELINE["minimum_age_days"] * 1440:
        assessment["minimum_age"] = "[red]✗ Too Short[/red]"
    else:
        assessment["minimum_age"] = "[green]✓ OK[/green]"

    #---------------------------------------------------------------------------
    # COMPLEXITY
    #---------------------------------------------------------------------------    

    if policy["complexity"] == "Disabled":
        assessment["complexity"] = "[red]✗ Disabled[/red]"
    elif policy["complexity"] == "Enabled":
        assessment["complexity"] = "[green]✓ OK[/green]"
    else:
        assessment["complexity"] = UNKNOWN

    if "reversible_encryption" in policy:
        if policy["reversible_encryption"] == "Enabled":
            assessment["reversible_encryption"] = "[red]✗ Enabled[/red]"
        elif policy["reversible_encryption"] == "Disabled":
            assessment["reversible_encryption"] = "[green]✓ Disabled[/green]"
        else:
            assessment["reversible_encryption"] = UNKNOWN

    #---------------------------------------------------------------------------
    # OBSERVATION WINDOW
    #---------------------------------------------------------------------------

    observation_window = duration_to_minutes(
        policy["observation_window"]
    )

    threshold = policy["lockout_threshold"]
    if threshold.isdecimal() and int(threshold) == 0:
        assessment["observation_window"] = "[yellow]Not applicable[/yellow]"
    elif not threshold.isdecimal() or observation_window is None:
        assessment["observation_window"] = UNKNOWN
    elif observation_window < PASSWORD_POLICY_BASELINE["observation_window_minutes"]:
        assessment["observation_window"] = (
            "[red]✗ Too Short[/red]"
        )
    else:
        assessment["observation_window"] = (
            "[green]✓ OK[/green]"
        )

    #---------------------------------------------------------------------------
    # LOCKOUT DURATION
    #---------------------------------------------------------------------------

    lockout_duration = duration_to_minutes(
        policy["lockout_duration"]
    )

    if threshold.isdecimal() and int(threshold) == 0:
        assessment["lockout_duration"] = "[yellow]Not applicable[/yellow]"
    elif threshold.isdecimal() and policy["lockout_duration"] == MANUAL_UNLOCK:
        assessment["lockout_duration"] = "[green]✓ Manual unlock[/green]"
    elif not threshold.isdecimal() or lockout_duration is None:
        assessment["lockout_duration"] = UNKNOWN
    elif lockout_duration == 0:
        assessment["lockout_duration"] = "[green]✓ Manual unlock[/green]"
    elif lockout_duration < PASSWORD_POLICY_BASELINE["lockout_duration_minutes"]:
        assessment["lockout_duration"] = (
            "[red]✗ Too Short[/red]"
        )
    else:
        assessment["lockout_duration"] = (
            "[green]✓ OK[/green]"
        )

    #---------------------------------------------------------------------------
    # LOCKOUT THRESHOLD
    #---------------------------------------------------------------------------

    if not policy["lockout_threshold"].isdecimal():
        assessment["lockout_threshold"] = UNKNOWN
    elif int(policy["lockout_threshold"]) == 0 or int(policy["lockout_threshold"]) > 10:
        assessment["lockout_threshold"] = (
            "[red]✗ Too Permissive[/red]"
        )
    else:
        assessment["lockout_threshold"] = (
            "[green]✓ OK[/green]"
        )

    return assessment