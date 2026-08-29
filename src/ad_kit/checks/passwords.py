"""
Password-related assessment checks.
"""

from ad_kit.core.checks import run_check


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
    complexity = "Unknown"
    lockout_threshold = "Unknown"

    for line in output.splitlines():

        line = line.strip()

        if "Minimum password length:" in line:
            minimum_length = (
                line.split(":")[-1]
                .strip()
            )

        elif "Password history length:" in line:
            password_history = (
                line.split(":")[-1]
                .strip()
            )

        elif "Maximum password age:" in line:
            maximum_age = (
                line.split(":", 1)[1]
                .strip()
            )

        elif "Domain Password Complex:" in line:
            value = (
                line.split(":")[-1]
                .strip()
            )

            complexity = (
                "Enabled"
                if value == "1"
                else "Disabled"
            )

        elif "Account Lockout Threshold:" in line:
            lockout_threshold = (
                line.split(":")[-1]
                .strip()
            )

    return {
        "minimum_length": minimum_length,
        "password_history": password_history,
        "maximum_age": maximum_age,
        "complexity": complexity,
        "lockout_threshold": lockout_threshold,
    }