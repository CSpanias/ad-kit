"""Advisory prerequisites and impact summaries for assessment workflows."""

import json
from pathlib import Path
from shutil import which

import typer

from ad_kit.core.console import console, print_info, print_section, print_success, print_warning
from ad_kit.core.util import ARTEFACTS_DIR

CHECK_TOOLS = {
    "asreproast": (("GetNPUsers.py", "impacket"),),
    "kerberoast": (("GetUserSPNs.py", "impacket"),),
    "privileged": (("bloodyAD", "bloodyad"), ("dacledit.py", "impacket")),
    "dns": (("bloodyAD", "bloodyad"),),
    "adcs": (("certipy", "certipy"),),
}

CHECK_IMPACTS = {
    "maq": "MAQ may create a temporary computer account and attempt to remove it.",
    "dns": "DNS may create a temporary DNS record and attempt to remove it.",
    "asreproast": "AS-REP roasting requests and saves crackable Kerberos responses.",
    "kerberoast": "Kerberoasting requests and saves crackable service tickets.",
    "coercion": "Coercion actively probes authentication coercion methods on DCs.",
    "nopac": "NoPAC sends Kerberos vulnerability probes to DCs.",
}


def _warn_missing_tools(tools: dict[str, str]) -> bool:
    missing = False
    for executable, package in tools.items():
        if which(executable) is None:
            missing = True
            print_warning(
                f"'{executable}' is not on PATH. Install it with "
                f"'ad-kit tools install {package}' and check 'ad-kit tools status'."
            )
    return missing


def check_preflight(modules: list[str]) -> None:
    """Warn about known prerequisites without preventing partial execution."""
    print_section("Preflight")
    tools = {"nxc": "netexec"}
    for module in modules:
        tools.update(CHECK_TOOLS.get(module, ()))
    missing = _warn_missing_tools(tools)

    session_path = ARTEFACTS_DIR / "session.json"
    session = None
    if any(module != "ldap" for module in modules):
        try:
            session = json.loads(session_path.read_text(encoding="utf-8"))
            if not isinstance(session, dict):
                raise ValueError("session metadata is not an object")
        except (OSError, ValueError) as exc:
            print_warning(f"Cannot read assessment session ({exc}). Run 'ad-kit enum'.")
            session = None
            missing = True

    required_files: dict[str, set[str]] = {}
    for module in modules:
        if module in {"ldap", "smb", "delegation", "coercion"}:
            required_files.setdefault("dc-hostnames.txt", set()).add(module)
        if module == "smb":
            required_files.setdefault("domain-computers.txt", set()).add(module)
        if module == "asreproast":
            required_files.setdefault("domain-users-filtered.txt", set()).add(module)
    for filename, checks in required_files.items():
        if not (ARTEFACTS_DIR / filename).is_file():
            print_warning(
                f"{filename} is missing for {', '.join(sorted(checks))}. Run 'ad-kit enum'."
            )
            missing = True

    if session is not None:
        for key, label in (("domain", "domain"), ("dc_ip", "Domain Controller IP")):
            if not isinstance(session.get(key), str) or not session[key].strip():
                print_warning(f"Assessment session has no {label}. Run 'ad-kit enum'.")
                missing = True
        if any(module not in {"ldap", "smb", "asreproast"} for module in modules):
            user = session.get("standard_user")
            if not isinstance(user, str) or not user.strip():
                print_warning(
                    "No Standard User is configured for authenticated checks. Run 'ad-kit enum'."
                )
                missing = True
        for key, label, checks in (
            ("domain_computers_exported", "Domain computer", {"smb", "local-admin"}),
            ("domain_users_exported", "Domain user", {"asreproast"}),
        ):
            selected = checks.intersection(modules)
            if selected and session.get(key) is not True:
                print_warning(
                    f"{label} collection is incomplete for {', '.join(sorted(selected))}. "
                    "Run 'ad-kit enum'."
                )
                missing = True

    if not missing:
        print_success("Known local prerequisites are available.")
    else:
        print_info("Checks will continue; missing prerequisites may leave gaps in results.")


def enum_preflight(*, collect: bool, dump_ntds: bool, retrieval: bool) -> None:
    """Warn about tools required by the selected enumeration options."""
    print_section("Preflight")
    tools = {"nxc": "netexec"}
    if collect:
        tools["rusthound-ce"] = "rusthound"
    if dump_ntds:
        tools["secretsdump.py"] = "impacket"
    if not (Path.home() / ".nxc" / "nxc.conf").exists():
        tools["netexec"] = "netexec"
    missing = _warn_missing_tools(tools)
    if retrieval and which("ip") is None:
        print_warning("'ip' is not on PATH; SCP retrieval address selection may fail.")
        missing = True
    if not missing:
        print_success("Known local prerequisites are available.")
    else:
        print_info("Enumeration will continue; missing tools may prevent selected steps.")


def confirm_check_impact(modules: list[str]) -> bool:
    """Describe the selected checks and confirm potentially impactful actions."""
    print_section("Assessment Impact")
    print_info("Selected checks: " + ", ".join(modules))
    impacts = [CHECK_IMPACTS[module] for module in dict.fromkeys(modules) if module in CHECK_IMPACTS]
    for impact in impacts:
        print_warning(impact)
    if not impacts:
        print_info("Selected checks query or probe targets; no test object creation is planned.")
        return True
    if "maq" in modules or "dns" in modules:
        print_warning("Cleanup can fail; manual removal may be required.")
    console.print()
    return typer.confirm("Continue with these checks?", default=False)


def confirm_enum_impact(*, collect: bool, dump_ntds: bool) -> bool:
    """Describe enumeration collection and confirm NTDS extraction."""
    print_section("Assessment Impact")
    print_info("Enumeration queries AD and saves collected account and computer data.")
    print_info("NetExec's local audit mode configuration may be updated.")
    if collect:
        print_info("RustHound collection saves directory data for BloodHound.")
    if not dump_ntds:
        return True
    print_warning("NTDS extraction requests and saves sensitive password hashes.")
    console.print()
    return typer.confirm("Continue with enumeration and NTDS extraction?", default=False)
