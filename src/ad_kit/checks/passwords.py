"""
Password-related assessment checks.
"""

from ad_kit.core.checks import (
    run_check, 
    PASSWORD_POLICY_BASELINE, 
    duration_to_minutes
)


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

    minimum_length = "[yellow]⚠ Unknown[/yellow]"
    password_history = "[yellow]⚠ Unknown[/yellow]"
    maximum_age = "[yellow]⚠ Unknown[/yellow]"
    minimum_age = "[yellow]⚠ Unknown[/yellow]"
    complexity = "[yellow]⚠ Unknown[/yellow]"
    observation_window = "[yellow]⚠ Unknown[/yellow]"
    lockout_duration = "[yellow]⚠ Unknown[/yellow]"
    lockout_threshold = "[yellow]⚠ Unknown[/yellow]"

    for line in output.splitlines():

        line = line.strip()

        if "Minimum password length:" in line:
            minimum_length = (line.split(":")[-1].strip())

        elif "Password history length:" in line:
            password_history = (line.split(":")[-1].strip())

        elif "Maximum password age:" in line:
            maximum_age = (line.split(":", 1)[1].strip())

        elif "Minimum password age:" in line:
            minimum_age = (line.split(":", 1)[1].strip())

        elif "Domain Password Complex:" in line:
            value = (line.split(":")[-1].strip())
            complexity = ("Enabled" if value == "1" else "Disabled")

        elif "Reset Account Lockout Counter:" in line:
            observation_window = (line.split(":", 1)[1].strip())

        elif "Locked Account Duration:" in line:
            lockout_duration = (line.split(":", 1)[1].strip())

        elif "Account Lockout Threshold:" in line:
            lockout_threshold = (line.split(":")[-1].strip())

    return {
        "minimum_length": minimum_length,
        "password_history": password_history,
        "maximum_age": maximum_age,
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

    # Minimum Length
    if (
        policy["minimum_length"].isdigit()
        and int(policy["minimum_length"])
        < PASSWORD_POLICY_BASELINE["minimum_length"]
    ):
        assessment["minimum_length"] = "[red]✗ Too Short[/red]"
    else:
        assessment["minimum_length"] = "[green]✓ OK[/green]"

    # Password History
    if (
        policy["password_history"].isdigit()
        and int(policy["password_history"])
        < PASSWORD_POLICY_BASELINE["password_history"]
    ):
        assessment["password_history"] = "[red]✗ Too Low[/red]"
    else:
        assessment["password_history"] = "[green]✓ OK[/green]"

    # Minimum Age
    if (
        policy["minimum_age"] != "[yellow]⚠ Unknown[/yellow]"
        and policy["minimum_age"].startswith("0")
    ):
        assessment["minimum_age"] = "[red]✗ Not Set[/red]"
    else:
        assessment["minimum_age"] = "[green]✓ OK[/green]"

    # Maximum Age
    if (
        policy["maximum_age"] != "[yellow]⚠ Unknown[/yellow]"
        and (
            policy["maximum_age"].startswith("0")
            or "not set" in policy["maximum_age"].lower()
        )
    ):
        assessment["maximum_age"] = "[red]✗ Not Set[/red]"
    else:
        assessment["maximum_age"] = "[green]✓ OK[/green]"

    # Complexity
    if policy["complexity"] == "Disabled":
        assessment["complexity"] = "[red]✗ Disabled[/red]"
    else:
        assessment["complexity"] = "[green]✓ OK[/green]"

    # Observation Window
    observation_window = duration_to_minutes(
        policy["observation_window"]
    )

    if (
        observation_window is not None
        and observation_window
        < PASSWORD_POLICY_BASELINE[
            "observation_window_minutes"
        ]
    ):
        assessment["observation_window"] = (
            "[red]✗ Too Short[/red]"
        )
    else:
        assessment["observation_window"] = (
            "[green]✓ OK[/green]"
        )

    # Lockout Duration
    lockout_duration = duration_to_minutes(
        policy["lockout_duration"]
    )

    if (
        lockout_duration is not None
        and lockout_duration
        < PASSWORD_POLICY_BASELINE[
            "lockout_duration_minutes"
        ]
    ):
        assessment["lockout_duration"] = (
            "[red]✗ Too Short[/red]"
        )
    else:
        assessment["lockout_duration"] = (
            "[green]✓ OK[/green]"
        )

    # Lockout Threshold
    if (
        policy["lockout_threshold"].isdigit()
        and (
            int(policy["lockout_threshold"]) == 0
            or int(policy["lockout_threshold"]) > 10
        )
    ):
        assessment["lockout_threshold"] = (
            "[red]✗ Too Permissive[/red]"
        )
    else:
        assessment["lockout_threshold"] = (
            "[green]✓ OK[/green]"
        )

    return assessment