"""
Password-related assessment checks.
"""

from ad_kit.core.checks import PASSWORD_POLICY_BASELINE, duration_to_minutes, run_check

UNKNOWN = "[yellow]⚠ Unknown[/yellow]"


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

    return {
        "minimum_length": minimum_length,
        "password_history": password_history,
        "minimum_age": minimum_age,
        "complexity": complexity,
        "observation_window": observation_window,
        "lockout_duration": lockout_duration,
        "lockout_threshold": lockout_threshold,
    }


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
    elif threshold.isdecimal() and policy["lockout_duration"].strip().lower() == "not set":
        assessment["lockout_duration"] = "[yellow]Review (not set)[/yellow]"
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