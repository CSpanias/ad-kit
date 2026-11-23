import io
import subprocess
import sys
from contextlib import contextmanager

import pytest
from rich.console import Console

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
    assert progress_messages == ["Running check..."]
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
    assert messages == ["Running check..."]
    assert "-u '' -p ''" in evidence


def test_nxc_progress_streams_without_leaking_or_corrupting_evidence(monkeypatch, tmp_path):
    display = io.StringIO()
    updates = []
    original_update = checks.Progress.update

    def update(tracker, task_id, **kwargs):
        updates.append(kwargs.get("completed"))
        return original_update(tracker, task_id, **kwargs)

    monkeypatch.setattr(checks.Progress, "update", update)
    monkeypatch.setattr(checks, "console", Console(file=display, force_terminal=True))
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    script = """
import sys, time
from rich.console import Console
from rich.progress import Progress
console = Console(soft_wrap=True, tab_size=4)
with Progress(console=console) as progress:
    task = progress.add_task("Running nxc against 2 targets", total=2)
    time.sleep(0.25)
    console.print(f"SMB 10.0.0.1 445 HOST [+] user:{sys.argv[-1]} (Pwn3d!)")
    sys.__stderr__.write(f"failure involving {sys.argv[-1]}\\n")
    sys.__stderr__.flush()
    progress.update(task, advance=1)
    time.sleep(0.35)
    progress.update(task, advance=1)
    time.sleep(0.2)
"""
    with checks.capture_check_evidence() as records:
        output = checks.run_check(
            "nxc-progress", [sys.executable, "-c", script, "-p", "test-secret"],
            nxc_progress=True,
        )

    evidence = (tmp_path / "evidence" / "nxc-progress.txt").read_text(encoding="utf-8")
    assert "SMB 10.0.0.1 445 HOST [+] user:[REDACTED] (Pwn3d!)" in output
    assert "Running nxc against" not in output
    assert "test-secret" not in output
    assert "test-secret" not in evidence
    assert "test-secret" not in display.getvalue()
    assert sys.executable not in display.getvalue()
    assert 50 in updates and 100 in updates
    assert "50%" in display.getvalue()
    assert "failure involving [REDACTED]" in records[0].stderr


def test_nxc_progress_falls_back_when_no_progress_is_emitted(monkeypatch, tmp_path):
    display = io.StringIO()
    monkeypatch.setattr(checks, "console", Console(file=display, force_terminal=True))
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    output = checks.run_check(
        "nxc-fallback",
        [sys.executable, "-c", "import time; time.sleep(0.2); print('SMB result')"],
        nxc_progress=True,
    )
    assert output == "SMB result"
    assert "NetExec targets" in display.getvalue()
    assert sys.executable not in display.getvalue()
    assert sys.executable in (tmp_path / "evidence" / "nxc-fallback.txt").read_text(
        encoding="utf-8"
    )


def test_nxc_progress_uses_normal_capture_for_noninteractive_output(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(checks, "console", Console(file=io.StringIO(), force_terminal=False))
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        checks, "progress", lambda *_args: pytest.fail("unexpected command progress")
    )
    monkeypatch.setattr(
        checks.subprocess, "run",
        lambda command, **kwargs: (
            calls.append((command, kwargs))
            or subprocess.CompletedProcess(command, 0, stdout="SMB result\n", stderr="")
        ),
    )
    output = checks.run_check("nxc-noninteractive", ["nxc", "smb", "hosts"], nxc_progress=True)
    assert output == "SMB result\n"
    assert calls == [(["nxc", "smb", "hosts"], {"capture_output": True, "text": True})]
    evidence = (tmp_path / "evidence" / "nxc-noninteractive.txt").read_text(encoding="utf-8")
    assert "$ nxc smb hosts" in evidence


def test_nxc_progress_preserves_failed_command_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(checks, "console", Console(file=io.StringIO(), force_terminal=True))
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    script = "import sys; print(sys.argv[-1]); sys.stderr.write(sys.argv[-1]); sys.exit(2)"
    with pytest.raises(CheckExecutionError) as error:
        checks.run_check(
            "nxc-failed", [sys.executable, "-c", script, "-p", "test-secret"],
            nxc_progress=True,
        )
    evidence = (tmp_path / "evidence" / "nxc-failed.txt").read_text(encoding="utf-8")
    assert error.value.returncode == 2
    assert error.value.stderr == "[REDACTED]"
    assert "test-secret" not in evidence


def test_nxc_progress_drains_stderr_and_redacts_ansi_wrapped_secrets(monkeypatch, tmp_path):
    monkeypatch.setattr(checks, "console", Console(file=io.StringIO(), force_terminal=True))
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    script = (
        "import sys; "
        "sys.stderr.write('x' * 100000 + sys.argv[-1]); sys.stderr.flush(); "
        "sys.stdout.write('value ' + sys.argv[-1][:4] + '\\x1b[31m' + sys.argv[-1][4:])"
    )
    with checks.capture_check_evidence() as records:
        output = checks.run_check(
            "nxc-ansi", [sys.executable, "-c", script, "-p", "test-secret"],
            nxc_progress=True,
        )
    assert output == "value [REDACTED]"
    assert records[0].stderr.endswith("[REDACTED]")
