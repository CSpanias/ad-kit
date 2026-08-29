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

    minimum_length = "Unknown"
    password_history = "Unknown"
    maximum_age = "Unknown"
    minimum_age = "Unknown"
    complexity = "Unknown"
    observation_window = "Unknown"
    lockout_duration = "Unknown"
    lockout_threshold = "Unknown"

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

from ad_kit.core.checks import (
    PASSWORD_POLICY_BASELINE,
)


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
        assessment["minimum_length"] = "[yellow]⚠ Too Short[/yellow]"
    else:
        assessment["minimum_length"] = "[green]✓ OK[/green]"

    # Password History
    if (
        policy["password_history"].isdigit()
        and int(policy["password_history"])
        < PASSWORD_POLICY_BASELINE["password_history"]
    ):
        assessment["password_history"] = "[yellow]⚠ Too Low[/yellow]"
    else:
        assessment["password_history"] = "[green]✓ OK[/green]"

    # Minimum Age
    if (
        policy["minimum_age"] != "Unknown"
        and policy["minimum_age"].startswith("0")
    ):
        assessment["minimum_age"] = "[yellow]⚠ Not Set[/yellow]"
    else:
        assessment["minimum_age"] = "[green]✓ OK[/green]"

    # Maximum Age
    if (
        policy["maximum_age"] != "Unknown"
        and (
            policy["maximum_age"].startswith("0")
            or "not set" in policy["maximum_age"].lower()
        )
    ):
        assessment["maximum_age"] = "[yellow]⚠ Not Set[/yellow]"
    else:
        assessment["maximum_age"] = "[green]✓ OK[/green]"

    # Complexity
    if policy["complexity"] == "Disabled":
        assessment["complexity"] = "[yellow]⚠ Disabled[/yellow]"
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
            "[yellow]⚠ Too Short[/yellow]"
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
            "[yellow]⚠ Too Short[/yellow]"
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
            "[yellow]⚠ Too Permissive[/yellow]"
        )
    else:
        assessment["lockout_threshold"] = (
            "[green]✓ OK[/green]"
        )

    return assessment