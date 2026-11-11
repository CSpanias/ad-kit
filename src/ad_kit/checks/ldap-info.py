"""
LDAP information exposure assessment checks.
"""

from ad_kit.core.checks import run_check


LDAP_SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "credential",
    "token",
    "apikey",
    "api key",
    "vpn",
    "ssh",
    "rdp",
    "sql",
)

def ldap_info_check(
    dc_ip: str,
    username: str,
    password: str,
) -> dict:
    """
    Review LDAP attributes for potentially sensitive information exposure.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            LDAP username.

        password:
            LDAP password.

    Returns:
        Dictionary containing exposed LDAP attribute values.
    """

    desc_output = run_check(
        "ldap-desc-users",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "-M",
            "get-desc-users",
        ],
    )

    info_output = run_check(
        "ldap-info-users",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "-M",
            "get-info-users",
        ],
    )

    user_password_output = run_check(
        "ldap-user-password",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "-M",
            "get-userPassword",
        ],
    )

    unix_password_output = run_check(
        "ldap-unix-password",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "-M",
            "get-unixUserPassword",
        ],
    )

    descriptions = []
    info_fields = []
    user_passwords = []
    unix_passwords = []

    #---------------------------------------------------------------------------
    # DESCRIPTIONS
    #---------------------------------------------------------------------------

    for line in desc_output.splitlines():

        if "User:" not in line:
            continue

        if "description:" not in line:
            continue

        user = (
            line.split("User:", 1)[1]
            .split("description:", 1)[0]
            .strip()
        )

        description = (
            line.split("description:", 1)[1]
            .strip()
        )

        descriptions.append(
            {
                "user": user,
                "value": description,
            }
        )

    #---------------------------------------------------------------------------
    # INFO FIELD
    #---------------------------------------------------------------------------

    for line in info_output.splitlines():

        if "User:" not in line:
            continue

        if "info:" not in line.lower():
            continue

        user = (
            line.split("User:", 1)[1]
            .split("info:", 1)[0]
            .strip()
        )

        value = (
            line.lower()
            .split("info:", 1)[1]
            .strip()
        )

        info_fields.append(
            {
                "user": user,
                "value": value,
            }
        )

    #---------------------------------------------------------------------------
    # userPassword
    #---------------------------------------------------------------------------

    for line in user_password_output.splitlines():

        if "User:" not in line:
            continue

        user_passwords.append(line.strip())

    #---------------------------------------------------------------------------
    # unixUserPassword
    #---------------------------------------------------------------------------

    for line in unix_password_output.splitlines():

        if "User:" not in line:
            continue

        unix_passwords.append(line.strip())

    return {
        "descriptions": descriptions,
        "info_fields": info_fields,
        "user_passwords": user_passwords,
        "unix_passwords": unix_passwords,
    }


def is_sensitive_value(
    value: str,
) -> bool:
    """
    Determine whether an LDAP attribute value contains potentially sensitive 
    information.

    The supplied value is compared against a predefined set of keywords 
    commonly associated with credentials, authentication mechanisms, secrets, 
    infrastructure information, and other sensitive administrative data.

    Args:
        value:
            LDAP attribute value to assess.

    Returns:
        True if the value contains one or more sensitive keywords. Otherwise, 
        False.
    """

    value = value.lower()

    return any(
        keyword in value
        for keyword in LDAP_SENSITIVE_KEYWORDS
    )