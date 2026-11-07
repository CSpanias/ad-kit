"""
Machine Account Quota assessment checks.
"""

import secrets

from ad_kit.core.checks import run_check


def maq_check(
    dc_ip: str,
    username: str,
    password: str,
) -> dict:
    """
    Retrieve and assess the domain Machine Account
    Quota configuration.

    The check authenticates to Active Directory using
    the supplied credentials and retrieves Machine
    Account Quota settings together with delegated
    permissions that allow users to join devices to
    the domain.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Domain password.

    Returns:
        Dictionary containing Machine Account Quota configuration and 
        machine-account creation test results.
    """

    output = run_check(
        "maq",
        [
            "nxc",
            "ldap",
            dc_ip,
            "-u",
            username,
            "-p",
            password,
            "-M",
            "maq",
        ],
    )

    machine_name = f"ADKIT-{secrets.token_hex(4).upper()}"
    machine_password = secrets.token_hex(8)

    results = {
        "machine_account_quota": "Unknown",
        "machine_join_group": "Unknown",

        "machine_name": machine_name,
        "machine_password": machine_password,

        "machine_created": False,
        "machine_authenticated": False,
        "machine_deleted": False,

        "cleanup_method": "None",
    }

    for line in output.splitlines():

        if "MachineAccountQuota:" in line:

            maq = int(
                line.split(":")[-1].strip()
            )

            results[
                "machine_account_quota"
            ] = str(maq)

        elif "Authenticated Users" in line:

            results[
                "machine_join_group"
            ] = "Authenticated Users"


    maq = results["machine_account_quota"]

    if maq != "Unknown" and int(maq) > 0:

        create_output = run_check(
            "maq-create-machine",
            [
                "nxc",
                "smb",
                dc_ip,
                "-u",
                username,
                "-p",
                password,
                "-M",
                "add-computer",
                "-o",
                f"NAME={machine_name}",
                f"PASSWORD={machine_password}",
            ],
        )

        if "successfully added" in create_output.lower():

            results["machine_created"] = True

            # Machine validation
            auth_output = run_check(
                "maq-auth-machine",
                [
                    "nxc",
                    "smb",
                    dc_ip,
                    "-u",
                    f"{machine_name}$",
                    "-p",
                    machine_password,
                ],
            )

            if "[+]" in auth_output:

                results["machine_authenticated"] = True

            # Machine removal
            delete_output = run_check(
                "maq-delete-machine",
                [
                    "nxc",
                    "smb",
                    dc_ip,
                    "-u",
                    username,
                    "-p",
                    password,
                    "-M",
                    "add-computer",
                    "-o",
                    f"NAME={machine_name}",
                    f"PASSWORD={machine_password}",
                    "DELETE=True",
                ],
            )

            if "successfully deleted" in delete_output.lower():

                results["machine_deleted"] = True
                results["cleanup_method"] = "Standard User"

            elif "does not have the right to delete" in delete_output.lower():

                results["cleanup_method"] = "Domain Admin Required"

    return results