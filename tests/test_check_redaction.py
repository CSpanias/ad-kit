import subprocess
from contextlib import contextmanager

from ad_kit.core import checks


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
