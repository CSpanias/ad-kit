import typer

from ad_kit.core.checks import validate_credentials
from ad_kit.core.console import console, print_error, print_success
from ad_kit.core.util import progress, require_session


def authenticate_standard_user(*, trailing_blank: bool = True) -> str:
    """
    Prompt for and validate Standard User credentials.

    The user is prompted to enter the password for the Standard User account 
    stored in the assessment session. Authentication is validated against the
    target domain before authenticated checks are executed.

    Returns:
        The validated Standard User password.

    Raises:
        RuntimeError:
            If authentication cannot be completed.
    """

    session_data = require_session()

    while True:

        std_pass = typer.prompt(
            "Enter the Standard User password",
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
            if trailing_blank:
                console.print()
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

def authenticate_domain_admin() -> tuple[str, str]:
    """
    Prompt for and validate Domain Administrator (DA) credentials.

    The user is prompted to provide credentials for a DA account. 
    Authentication is validated against the target domain before the 
    credentials are returned to the caller.

    Returns:
        Tuple containing:

        - Domain Administrator username
        - Domain Administrator password

    Raises:
        RuntimeError:
            If authentication cannot be completed.
    """

    session_data = require_session()

    while True:

        da_user = typer.prompt("Domain Administrator Username")

        da_pass = typer.prompt("Domain Administrator Password", hide_input=True)

        console.print()

        with progress("Validating credentials..."):

            status = validate_credentials(
                session_data["dc_ip"],
                da_user,
                da_pass,
            )

        if status == "valid":

            print_success("Authentication succeeded.")
            console.print()

            return da_user, da_pass

        if status == "locked":

            print_error("Account is locked out.")

        elif status == "invalid":

            print_error("Invalid credentials.")

        else:

            print_error("Unable to validate credentials.")

        if not typer.confirm("Try again?", default=True):
            raise RuntimeError("Authentication cancelled.")
