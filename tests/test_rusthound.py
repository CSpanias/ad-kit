import subprocess

from ad_kit.commands import rusthound


def test_rusthound_redacts_password_from_failure_output(monkeypatch, tmp_path):
    password = "Password123!"
    errors = []

    monkeypatch.setattr(rusthound, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(rusthound, "print_info", lambda *_args: None)
    monkeypatch.setattr(rusthound, "print_success", lambda *_args: None)
    monkeypatch.setattr(rusthound, "print_error", errors.append)
    monkeypatch.setattr(
        rusthound.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr=f"Authentication failed for {password}",
        ),
    )

    assert not rusthound.run_rusthound(
        "example.test",
        "192.0.2.1",
        "user",
        password,
    )
    assert password not in "\n".join(errors)
    assert "[REDACTED]" in "\n".join(errors)
