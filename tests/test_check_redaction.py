import subprocess
from contextlib import contextmanager

import pytest

from ad_kit.core import checks
from ad_kit.core.exceptions import CheckExecutionError


def test_run_check_redacts_password_from_progress_and_evidence(
    monkeypatch,
    tmp_path,
):
    password = "Password123!"
    machine_password = "MachinePass456!"
    progress_messages = []

    @contextmanager
    def fake_progress(message):
        progress_messages.append(message)
        yield

    def fake_run(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                f"Authenticated using {password} and "
                f"machine password {machine_password}"
            ),
            stderr=f"Error involving {password} and {machine_password}",
        )

    monkeypatch.setattr(checks, "progress", fake_progress)
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(checks.subprocess, "run", fake_run)

    output = checks.run_check(
        "redaction-test",
        [
            "nxc",
            "ldap",
            "dc.example.test",
            "-u",
            "user",
            "-p",
            password,
            "-o",
            f"PASSWORD={machine_password}",
        ],
    )

    evidence = (
        tmp_path / "evidence" / "redaction-test.txt"
    ).read_text(encoding="utf-8")

    assert password not in progress_messages[0]
    assert machine_password not in progress_messages[0]
    assert "[REDACTED]" in progress_messages[0]
    assert "PASSWORD=[REDACTED]" in progress_messages[0]
    assert password not in output
    assert machine_password not in output
    assert "[REDACTED]" in output
    assert password not in evidence
    assert machine_password not in evidence
    assert "Authenticated using [REDACTED]" in evidence
    assert "[stderr]\nError involving [REDACTED] and [REDACTED]" in evidence


def test_capture_is_current_run_redacted_and_preserves_failed_output(monkeypatch, tmp_path):
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        checks.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 1, stdout="secret output", stderr="secret error"
        ),
    )
    with checks.capture_check_evidence() as captured:
        with pytest.raises(CheckExecutionError):
            checks.run_check("failed", ["tool", "-p", "secret"])

    assert len(captured) == 1
    formatted = checks.format_check_evidence(captured[0])
    assert "secret" not in formatted
    assert "[REDACTED] output" in formatted
    assert "[stderr]\n[REDACTED] error" in formatted

    with checks.capture_check_evidence() as next_run:
        pass
    assert next_run == []


def test_redaction_handles_overlapping_passwords(monkeypatch, tmp_path):
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        checks.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout="foobar foo", stderr=""
        ),
    )
    with checks.capture_check_evidence() as captured:
        checks.run_check("overlap", ["tool", "-p", "foo", "PASSWORD=foobar"])
    assert captured[0].stdout == "[REDACTED] [REDACTED]"


def test_suppressed_command_progress_still_writes_redacted_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        checks, "progress", lambda *_args: pytest.fail("unexpected command progress")
    )
    monkeypatch.setattr(
        checks.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, stdout="secret", stderr=""
        ),
    )
    checks.run_check("quiet", ["tool", "-p", "secret"], show_progress=False)
    evidence = (tmp_path / "evidence" / "quiet.txt").read_text(encoding="utf-8")
    assert "secret" not in evidence
    assert "[REDACTED]" in evidence


def test_empty_arguments_are_preserved_in_display_and_execution(monkeypatch, tmp_path):
    messages = []
    commands = []

    @contextmanager
    def fake_progress(message):
        messages.append(message)
        yield

    def fake_run(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(checks, "progress", fake_progress)
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(checks.subprocess, "run", fake_run)
    command = ["nxc", "smb", "dc", "-u", "", "-p", "", "--shares"]
    checks.run_check("anonymous", command)

    evidence = (tmp_path / "evidence" / "anonymous.txt").read_text(encoding="utf-8")
    assert commands == [command]
    assert "-u '' -p ''" in messages[0]
    assert "-u '' -p ''" in evidence
