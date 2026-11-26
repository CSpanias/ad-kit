"""Assessment workflow orchestration and check dispatch."""

from collections.abc import Callable
from dataclasses import dataclass

from ad_kit.core.console import console as console
from ad_kit.core.console import print_error
from ad_kit.core.exceptions import ADKitError
from ad_kit.core.util import get_artefacts_dir, require_session
from ad_kit.reporting import results

from .checks.credentials import authenticate_standard_user
from .checks.hosts import run_nopac_checks, run_scriptpath_checks
from .checks.policy import (
    run_dns_checks,
    run_local_admin_checks,
    run_maq_checks,
    run_password_never_expires_checks,
    run_password_not_required_checks,
    run_password_policy_checks,
    run_pre2k_checks,
)
from .checks.privileged import (
    run_adcs_checks,
    run_coercion_checks,
    run_delegation_checks,
    run_kerberoast_checks,
    run_ldap_info_checks,
    run_privileged_group_checks,
)
from .checks.unauthenticated import (
    run_asreproast_checks,
    run_ldap_checks,
    run_smb_checks,
    run_tombstone_checks,
)

CheckRunner = Callable[[str | None], str | None]

@dataclass(frozen=True, slots=True)
class CheckDefinition:
    runner: CheckRunner
    requires_authentication: bool


def _without_password(check: Callable[[], None]) -> CheckRunner:
    def run(std_pass: str | None) -> str | None:
        check()
        return std_pass

    return run


def _with_password(check: Callable[[str | None], None]) -> CheckRunner:
    def run(std_pass: str | None) -> str | None:
        check(std_pass)
        return std_pass

    return run


def _run_step(
    module: str,
    runnable: Callable[[], str | None],
    std_pass: str | None,
) -> str | None:
    """
    Execute a single check step, skipping it gracefully if it fails.

    Args:
        module:
            Assessment module name, used for the skip notice.

        runnable:
            Zero-argument callable that executes the check.

        std_pass:
            Standard User password to reuse across checks.

    Returns:
        The password returned by the check, or the previously supplied
        password when the check returned none or was skipped.
    """

    try:
        result = runnable()
    except ADKitError as exc:
        print_error(f"Skipped '{module}': {exc}")
        results.record_incomplete(module, "", str(exc), notify=False)
        result = None

    return result if result is not None else std_pass


def _run_authed(
    module: str,
    check: CheckRunner,
    std_pass: str | None,
) -> str | None:
    """
    Execute an authenticated check step, skipping it if it fails.

    The supplied password is passed through to the check and propagated
    unchanged on success or skip.
    """

    return _run_step(module, lambda: check(std_pass), std_pass)


AVAILABLE_CHECKS: dict[str, CheckDefinition] = {
    "ldap": CheckDefinition(_without_password(lambda: run_ldap_checks()), False),
    "tombstone": CheckDefinition(
        _with_password(lambda password: run_tombstone_checks(password)), True
    ),
    "smb": CheckDefinition(lambda password: run_smb_checks(password), False),
    "asreproast": CheckDefinition(
        lambda password: run_asreproast_checks(password), False
    ),
    "pass-pol": CheckDefinition(
        _with_password(lambda password: run_password_policy_checks(password)), True
    ),
    "password-not-required": CheckDefinition(
        _with_password(lambda password: run_password_not_required_checks(password)), True
    ),
    "password-never-expires": CheckDefinition(
        _with_password(lambda password: run_password_never_expires_checks(password)), True
    ),
    "maq": CheckDefinition(_with_password(lambda password: run_maq_checks(password)), True),
    "dns": CheckDefinition(_with_password(lambda password: run_dns_checks(password)), True),
    "pre2k": CheckDefinition(
        _with_password(lambda password: run_pre2k_checks(password)), True
    ),
    "nopac": CheckDefinition(
        _with_password(lambda password: run_nopac_checks(password)), True
    ),
    "scriptPath": CheckDefinition(
        _with_password(lambda password: run_scriptpath_checks(password)), True
    ),
    "privileged": CheckDefinition(
        _with_password(lambda password: run_privileged_group_checks(password)), True
    ),
    "delegation": CheckDefinition(
        _with_password(lambda password: run_delegation_checks(password)), True
    ),
    "kerberoast": CheckDefinition(
        _with_password(lambda password: run_kerberoast_checks(password)), True
    ),
    "adcs": CheckDefinition(_with_password(lambda password: run_adcs_checks(password)), True),
    "local-admin": CheckDefinition(
        _with_password(lambda password: run_local_admin_checks(password)), True
    ),
    "ldap-info": CheckDefinition(
        _with_password(lambda password: run_ldap_info_checks(password)), True
    ),
    "coercion": CheckDefinition(
        _with_password(lambda password: run_coercion_checks(password)), True
    ),
}


def _export_domain(csacyber: bool) -> str | None:
    if not csacyber:
        return None
    session = require_session()
    domain = session.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError(
            "SureFormat export requires a domain in session metadata. Run 'ad-kit enum'."
        )
    return domain.strip()


def run_selected_checks(modules: list[str], *, csacyber: bool = False) -> None:
    """Execute selected checks, reusing one Standard User password."""
    domain = _export_domain(csacyber)
    results.reset()

    requires_authentication = any(
        module in AVAILABLE_CHECKS
        and AVAILABLE_CHECKS[module].requires_authentication
        for module in modules
    )

    std_pass = authenticate_standard_user(trailing_blank=False) if requires_authentication else None

    for module in modules:
        check = AVAILABLE_CHECKS.get(module)
        if check is None:
            print_error(f"Unknown module: {module}")
            continue
        std_pass = _run_step(
            module,
            lambda: check.runner(std_pass),
            std_pass,
        )

    run_name = "_".join(dict.fromkeys(
        module for module in modules if module in AVAILABLE_CHECKS
    )) or "selected"
    results.write_reports(
        get_artefacts_dir(), run_name=run_name, domain=domain,
        session=require_session() if csacyber else None,
    )


def run_checks(
    *, csacyber: bool = False, exclude: set[str] | None = None
) -> None:
    """Execute all assessment checks in the established workflow order."""
    excluded = exclude or set()
    unknown = excluded.difference(AVAILABLE_CHECKS)
    if unknown:
        raise ValueError("Unknown check(s): " + ", ".join(sorted(unknown)))
    if not set(AVAILABLE_CHECKS).difference(excluded):
        raise ValueError("At least one check must remain.")

    domain = _export_domain(csacyber)
    results.reset()

    std_pass = None
    if "ldap" not in excluded:
        _run_step("ldap", lambda: run_ldap_checks(), None)
    if "smb" not in excluded:
        std_pass = _run_step("smb", lambda: run_smb_checks(), None)
    if "asreproast" not in excluded:
        std_pass = _run_authed("asreproast", run_asreproast_checks, std_pass)

    authenticated_checks = (
        ("local-admin", run_local_admin_checks),
        ("pass-pol", run_password_policy_checks),
        ("password-not-required", run_password_not_required_checks),
        ("password-never-expires", run_password_never_expires_checks),
        ("maq", run_maq_checks),
        ("dns", run_dns_checks),
        ("pre2k", run_pre2k_checks),
        ("nopac", run_nopac_checks),
        ("scriptPath", run_scriptpath_checks),
        ("privileged", run_privileged_group_checks),
        ("delegation", run_delegation_checks),
        ("kerberoast", run_kerberoast_checks),
        ("adcs", run_adcs_checks),
        ("ldap-info", run_ldap_info_checks),
        ("tombstone", run_tombstone_checks),
        ("coercion", run_coercion_checks),
    )
    for module, runner in authenticated_checks:
        if module not in excluded:
            if std_pass is None:
                std_pass = authenticate_standard_user(trailing_blank=False)
            std_pass = _run_authed(module, runner, std_pass)

    results.write_reports(
        get_artefacts_dir(), domain=domain,
        session=require_session() if csacyber else None,
    )
