"""
Assessment check helpers.

This module provides shared functionality used by AD-Kit assessment checks, 
including evidence management, credential validation, command execution, and 
helper functions for loading enumerated Active Directory assets.
"""

import codecs
import os
import re
import shlex
import subprocess
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from ad_kit.core.console import console, print_warning
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.util import get_artefacts_dir, progress

#-------------------------------------------------------------------------------
# CONSTANTS
#-------------------------------------------------------------------------------

PASSWORD_POLICY_BASELINE = {
    "minimum_length": 12,
    "password_history": 2,
    "minimum_age_days": 1,
    "lockout_threshold": 5,
    "lockout_duration_minutes": 30,
    "observation_window_minutes": 15,
}

DOMAIN_SID_PATTERN = re.compile(r"\b(S-1-5-21-(?:\d+-){2}\d+)\b(?!-\d)", re.IGNORECASE)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
NXC_PROGRESS_PATTERN = re.compile(
    r"^Running nxc against \d+ targets?\s+.*?\s+(\d{1,3})%(?:\s|$)"
)

#-------------------------------------------------------------------------------
# FUNCTIONS
#-------------------------------------------------------------------------------

def parse_domain_sid(output: str) -> str:
    match = DOMAIN_SID_PATTERN.search(output)
    if match is None:
        raise RuntimeError("Could not determine the domain SID from NetExec output.")
    return match.group(1)


@dataclass(frozen=True)
class CheckEvidence:
    name: str
    command: list[str]
    stdout: str
    stderr: str


_evidence_capture: ContextVar[list[CheckEvidence] | None] = ContextVar(
    "check_evidence_capture", default=None
)


@contextmanager
def capture_check_evidence() -> Iterator[list[CheckEvidence]]:
    """Capture redacted results of commands executed in this context."""
    records: list[CheckEvidence] = []
    token = _evidence_capture.set(records)
    try:
        yield records
    finally:
        _evidence_capture.reset(token)


def append_captured_evidence(records: list[CheckEvidence]) -> None:
    captured = _evidence_capture.get()
    if captured is not None:
        captured.extend(records)


def clean_check_stderr(stderr: str) -> str:
    """Remove known interpreter noise without hiding command failures."""
    lines = stderr.splitlines()
    cleaned = []
    skip_source_line = False
    for line in lines:
        if re.search(
            r"(?i)(?:^|[/\\])badldap[/\\]wintypes[/\\]winerror\.py:\d+: "
            r"SyntaxWarning: .*invalid escape sequence",
            line,
        ):
            skip_source_line = True
            continue
        if skip_source_line and re.match(r"\s+0x[0-9A-Fa-f]+:", line):
            skip_source_line = False
            continue
        skip_source_line = False
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def format_check_evidence(record: CheckEvidence, stdout: str | None = None) -> str:
    output = record.stdout if stdout is None else stdout
    text = f"$ {shlex.join(record.command)}\n{output.rstrip()}"
    stderr = clean_check_stderr(record.stderr)
    if stderr:
        text += f"\n[stderr]\n{stderr}"
    return ANSI_ESCAPE_PATTERN.sub("", text)


def get_evidence_dir() -> Path:
    """
    Return the AD-Kit evidence directory.

    The evidence directory is used to store raw command output collected during 
    assessment checks. The directory is created automatically if it does not
    already exist.

    Returns:
        Path to the evidence directory.
    """

    evidence_dir = (get_artefacts_dir() / "evidence")
    evidence_dir.mkdir(exist_ok=True)

    return evidence_dir


def load_dc_ips() -> list:
    """
    Load enumerated Domain Controller IP addresses.

    Reads the Domain Controller IP address list generated during the 
    enumeration phase and returns the values as a list.

    Returns:
        List of Domain Controller IP addresses.
    """

    dc_ips_file = (get_artefacts_dir() / "dc-ips.txt")

    return [
        line.strip()
        for line in dc_ips_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_domain_computers() -> list:
    """
    Load enumerated domain computers.

    Reads the domain computer list generated during enumeration and returns the 
    values as a list.

    Returns:
        List of domain computer hostnames.
    """

    computers_file = (get_artefacts_dir() / "domain-computers.txt")

    return [
        line.strip()
        for line in computers_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_dc_hostnames() -> list:
    """
    Load enumerated Domain Controller hostnames.

    Reads the Domain Controller hostname list generated during enumeration and 
    returns the values as a list.

    Returns:
        List of Domain Controller hostnames.
    """

    dc_file = (get_artefacts_dir() / "dc-hostnames.txt")

    return [
        line.strip()
        for line in dc_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def duration_to_minutes(
    value: str,
) -> int | None:
    """
    Convert NetExec duration strings to minutes.

    This helper converts NetExec duration values such as '30 minutes', '2 hours 
    30 minutes', or '1 day 12 hours' into their equivalent number of minutes to 
    simplify password policy assessment logic.

    Args:
        value:
            NetExec duration string.

    Returns:
        Duration expressed in minutes, or None if the value cannot be 
        determined.
    """

    value = value.strip().lower()
    if value == "none":
        return 0

    if not re.fullmatch(
        r"\d+\s+(?:days?|hours?|minutes?)(?:\s+\d+\s+(?:days?|hours?|minutes?))*",
        value,
    ):
        return None

    minutes = 0

    tokens = value.split()

    for i, token in enumerate(tokens):

        if token in {"day", "days"}:
            minutes += int(tokens[i - 1]) * 1440

        elif token in {"hour", "hours"}:
            minutes += int(tokens[i - 1]) * 60

        elif token in {"minute", "minutes"}:
            minutes += int(tokens[i - 1])

    return minutes


def validate_credentials(
    dc_ip: str,
    username: str,
    password: str,
) -> str:
    """
    Validate Active Directory credentials.

    Authentication is performed against the target Domain Controller using 
    NetExec LDAP authentication.

    Args:
        dc_ip:
            Domain Controller IP address.

        username:
            Domain username.

        password:
            Account password.

    Returns:
        One of the following status values:

        - 'valid'
        - 'invalid'
        - 'locked'
        - 'unknown'
    """

    output = run_check(
        "credential-validation",
        ["nxc", "ldap", dc_ip,
            "-u", username,
            "-p", password,
        ],
        sensitive_values=[password],
    )

    for line in output.splitlines():

        lower = line.lower()

        if f"\\{username.lower()}:" not in lower:
            continue

        if "[+]" in line:
            return "valid"

        if "user_account_locked" in lower:
            return "locked"

        if "[-]" in line:
            return "invalid"

    return "unknown"


def warn_test_artifact_remaining(kind: str, name: str, evidence: str) -> None:
    evidence_path = get_artefacts_dir() / "evidence" / f"{evidence}.txt"
    print_warning(
        f"Cleanup of {kind} {name} was not confirmed; it may remain. "
        f"Check and remove it if necessary. Creation evidence: {evidence_path}"
    )


def cleanup_test_artifact(
    name: str,
    command: list[str],
) -> bool:
    """
    Attempt to remove a test artefact created during an assessment.

    The supplied cleanup command is executed and the result is evaluated to 
    determine whether the artefact was successfully removed.

    Args:
        name:
            Descriptive cleanup operation name.

        command:
            Command and arguments required to remove the artefact.

    Returns:
        True if the artefact was removed successfully, otherwise False.
    """

    SUCCESS_STRINGS = (
        "successfully removed",
        "successfully deleted",
    )

    output = run_check(name, command).lower()

    return any(
        success in output
        for success in SUCCESS_STRINGS
    )


def _run_nxc_with_progress(command: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["FORCE_COLOR"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if env.get("TERM") in (None, "", "dumb"):
        env["TERM"] = "xterm"

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}", markup=False),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as tracker:
        task = tracker.add_task("NetExec targets", total=None)
        with subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        ) as process:
            assert process.stdout is not None
            assert process.stderr is not None
            with ThreadPoolExecutor(max_workers=1) as executor:
                stderr_future = executor.submit(process.stderr.read)
                decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                output_parts: list[str] = []
                pending = ""
                try:
                    while chunk := process.stdout.read1(4096):
                        text = decoder.decode(chunk)
                        output_parts.append(text)
                        pending += text
                        lines = re.split(r"[\r\n]", pending)
                        pending = lines.pop()
                        for line in lines:
                            match = NXC_PROGRESS_PATTERN.match(
                                ANSI_ESCAPE_PATTERN.sub("", line)
                            )
                            if match and int(match.group(1)) <= 100:
                                tracker.update(task, total=100, completed=int(match.group(1)))
                    output_parts.append(decoder.decode(b"", final=True))
                    returncode = process.wait()
                    stderr = stderr_future.result().decode("utf-8", errors="replace")
                except BaseException:
                    if process.poll() is None:
                        process.kill()
                    raise

    output = ANSI_ESCAPE_PATTERN.sub("", "".join(output_parts))
    output = "\n".join(
        line for line in re.split(r"[\r\n]+", output)
        if line and not NXC_PROGRESS_PATTERN.match(line)
    )
    stderr = ANSI_ESCAPE_PATTERN.sub("", stderr)
    return subprocess.CompletedProcess(command, returncode, output, stderr)


def run_check(
    name: str,
    command: list[str],
    sensitive_values: list[str] | None = None,
    *,
    show_progress: bool = True,
    nxc_progress: bool = False,
) -> str:
    """
    Execute an assessment check and preserve evidence.

    The supplied command is executed, its output is written to the assessment 
    evidence directory, and the command stdout is returned to the caller for
    parsing. Sensitive values are redacted from progress output, saved
    evidence, and returned stdout. Values supplied with `-p`, `--password`,
    `--password=...`, or `PASSWORD=...` are redacted automatically.

    Args:
        name:
            Evidence filename prefix.

        command:
            Command and arguments to execute.

        sensitive_values:
            Command values to redact from progress output and saved evidence.

        show_progress:
            Whether to display an individual command activity indicator.

        nxc_progress:
            Display NetExec's multi-target progress when running interactively.

    Returns:
        Command standard output.

    Raises:
        CheckExecutionError:
            If the command binary cannot be found, or the command exits with a
            non-zero return code.
    """

    secrets = [
        value
        for value in (sensitive_values or [])
        if value
    ]

    for index, argument in enumerate(command):
        if argument in {"-p", "--password"} and index + 1 < len(command):
            password = command[index + 1]
        elif argument.casefold().startswith(("--password=", "password=")):
            password = argument.partition("=")[2]
        else:
            continue

        if password and password not in secrets:
            secrets.append(password)

    secrets.sort(key=len, reverse=True)

    display_command = []

    for argument in command:
        if argument in secrets:
            display_command.append("[REDACTED]")
        elif argument.casefold().startswith(("--password=", "password=")):
            option, _, value = argument.partition("=")
            display_command.append(
                f"{option}=[REDACTED]" if value in secrets else argument
            )
        else:
            display_command.append(argument)

    try:
        if nxc_progress and show_progress and console.is_terminal:
            result = _run_nxc_with_progress(command)
        else:
            activity = (
                progress("Running check...")
                if show_progress and not nxc_progress else nullcontext()
            )
            with activity:
                result = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise CheckExecutionError(
            name=name,
            command=display_command,
            stderr=f"command not found: {command[0]}",
        ) from exc

    output = result.stdout
    for secret in secrets:
        output = output.replace(secret, "[REDACTED]")

    error_output = result.stderr
    for secret in secrets:
        error_output = error_output.replace(secret, "[REDACTED]")

    evidence_file = (get_evidence_dir() / f"{name}.txt")
    evidence = (f"$ {shlex.join(display_command)}\n\n {output}")
    if error_output:
        evidence += f"\n\n[stderr]\n{error_output}"
    evidence_file.write_text(evidence, encoding="utf-8")

    records = _evidence_capture.get()
    if records is not None:
        records.append(CheckEvidence(name, display_command, output, error_output))

    if result.returncode != 0:
        raise CheckExecutionError(
            name=name,
            command=display_command,
            returncode=result.returncode,
            stderr=error_output,
        )

    return output