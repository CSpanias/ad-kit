import io
import struct
import subprocess
import sys
from contextlib import contextmanager

import pytest
from rich.console import Console

from ad_kit.core import checks
from ad_kit.core.exceptions import CheckExecutionError


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_kerberos_skew_prompts_and_retries_with_evidence(monkeypatch, tmp_path, stream):
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command, 1, stdout="KRB_AP_ERR_SKEW" if stream == "stdout" else "",
                stderr="KRB_AP_ERR_SKEW" if stream == "stderr" else "",
            )
        return subprocess.CompletedProcess(command, 0, stdout="success", stderr="")

    synced = []
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(checks.subprocess, "run", fake_run)
    monkeypatch.setattr(checks.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(checks.typer, "confirm", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(checks, "_sync_clock_to_dc", synced.append)

    with checks.capture_check_evidence() as records:
        output = checks.run_check(
            "pre2k", ["nxc", "-p", "secret"], kerberos_dc="192.0.2.10"
        )
    assert output == "success"
    assert len(calls) == 2
    assert synced == ["192.0.2.10"]
    assert len(records) == 2
    evidence = (tmp_path / "evidence" / "pre2k.txt").read_text(encoding="utf-8")
    assert "KRB_AP_ERR_SKEW" in evidence and "success" in evidence
    assert "secret" not in evidence


@pytest.mark.parametrize("case", ["declined", "noninteractive", "sync-failed", "retry-skew"])
def test_kerberos_skew_fails_explicitly_without_success(monkeypatch, tmp_path, case):
    calls = []
    monkeypatch.setattr(checks, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(checks.sys.stdin, "isatty", lambda: case != "noninteractive")
    monkeypatch.setattr(checks.typer, "confirm", lambda *_args, **_kwargs: case != "declined")

    def fake_run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="KRB_AP_ERR_SKEW", stderr="")

    def sync(_dc):
        if case == "sync-failed":
            raise OSError("NTP timed out")

    monkeypatch.setattr(checks.subprocess, "run", fake_run)
    monkeypatch.setattr(checks, "_sync_clock_to_dc", sync)
    with pytest.raises(CheckExecutionError) as error:
        checks.run_check("pre2k", ["nxc"], kerberos_dc="192.0.2.10")
    assert len(calls) == (2 if case == "retry-skew" else 1)
    assert "clock" in str(error.value).lower()
    if case == "sync-failed":
        assert "NTP timed out" in str(error.value)


@pytest.mark.parametrize("valid", [True, False])
def test_clock_sync_validates_dc_ntp_response(monkeypatch, valid):
    sent = []

    class NtpSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def settimeout(self, _timeout):
            pass

        def connect(self, address):
            assert address == ("192.0.2.10", 123)

        def sendall(self, request):
            sent.append(bytes(request))

        def recv(self, _size):
            response = bytearray(48)
            response[0] = 0x24
            response[1] = 2
            response[24:32] = sent[0][40:48]
            if not valid:
                response[24] ^= 1
            struct.pack_into("!II", response, 40, 2208989800, 0)
            return bytes(response)

    commands = []
    monkeypatch.setattr(checks.socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (2, 2, 17, "", ("192.0.2.10", 123)),
    ])
    monkeypatch.setattr(checks.socket, "socket", lambda *_args: NtpSocket())
    monkeypatch.setattr(checks.time, "time", lambda: 1000)
    monkeypatch.setattr(checks.time, "monotonic", lambda: 10)
    monkeypatch.setattr(checks.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(
        checks.subprocess, "run", lambda command, **kwargs: commands.append((command, kwargs))
    )
    with monkeypatch.context() as platform:
        platform.setattr(checks.os, "name", "posix")
        if valid:
            checks._sync_clock_to_dc("192.0.2.10")
        else:
            with pytest.raises(RuntimeError, match="Invalid NTP response"):
                checks._sync_clock_to_dc("192.0.2.10")
    assert commands == (
        [(["sudo", "date", "--set", "@1000.000000"], {"check": True})] if valid else []
    )


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


def test_format_check_evidence_filters_python_syntax_warnings():
    record = checks.CheckEvidence(
        "dns-record-create",
        ["bloodyAD", "add", "dnsRecord", "ad-kit-test", "192.0.2.1"],
        "[+] ad-kit-test has been successfully added",
        "/home/kali/tool/badldap/wintypes/winerror.py:13895: "
        "SyntaxWarning: \"\\<\" is an invalid escape sequence\n"
        '  0x80004017: { "code": "CO_E_RUNAS_SYNTAX" }\n'
        "/tmp/other.py:1: SyntaxWarning: invalid escape sequence\n"
        "actual tool error",
    )

    formatted = checks.format_check_evidence(record)

    assert "winerror.py" not in formatted
    assert "0x80004017" not in formatted
    assert (
        "[stderr]\n/tmp/other.py:1: SyntaxWarning: invalid escape sequence\nactual tool error"
    ) in formatted


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
