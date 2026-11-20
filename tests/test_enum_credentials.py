import json
import shlex
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from ad_kit.commands import enum
from ad_kit.core import util


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("[+] example.test\\alice:********", (True, False)),
        ("[+] example.test\\alice:******** (Pwn3d!)", (True, True)),
        ("[-] example.test\\alice:******** STATUS_LOGON_FAILURE", (False, False)),
    ],
)
def test_validate_credentials_uses_ldap_and_account_result(monkeypatch, line, expected):
    def run(command, **_kwargs):
        assert command == ["nxc", "ldap", "192.0.2.1", "-u", "alice", "-p", "secret"]
        return SimpleNamespace(
            returncode=0,
            stdout=f"[+] unrelated output (Pwn3d!)\nLDAP 192.0.2.1 389 DC01 {line}\n",
        )

    monkeypatch.setattr(enum.subprocess, "run", run)
    assert enum.validate_credentials("192.0.2.1", "alice", "secret") == expected


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [(1, ""), (0, "[+] unrelated output (Pwn3d!)")],
)
def test_validation_failure_does_not_infer_success(monkeypatch, returncode, stdout):
    monkeypatch.setattr(
        enum.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=returncode, stdout=stdout),
    )
    with pytest.raises(RuntimeError, match="LDAP credential validation"):
        enum.validate_credentials("192.0.2.1", "alice", "secret")


@pytest.mark.parametrize(
    "admin_output",
    [
        "[-] example.test\\admin:******** STATUS_LOGON_FAILURE",
        "[+] example.test\\admin:********",
        "",
    ],
)
def test_failed_admin_validation_continues_with_standard_user(monkeypatch, tmp_path, admin_output):
    prompts = iter(["192.0.2.1", "alice", "secret", "admin", "admin-secret"])
    confirms = iter([True, True, False, True, False])
    messages = []
    calls = []

    monkeypatch.setattr(enum.typer, "prompt", lambda *_args, **_kwargs: next(prompts))
    monkeypatch.setattr(enum.typer, "confirm", lambda *_args, **_kwargs: next(confirms))
    monkeypatch.setattr(enum, "identify_domain_controller", lambda _dc: ("DC01", "EXAMPLE.TEST"))
    monkeypatch.setattr(enum, "configure_nxc", lambda: None)

    def run(command, **_kwargs):
        calls.append(command)
        assert command[0:2] == ["nxc", "ldap"]
        output = (
            "[+] example.test\\alice:********"
            if command[4] == "alice" else admin_output
        )
        return SimpleNamespace(returncode=0, stdout=output)

    monkeypatch.setattr(enum.subprocess, "run", run)
    monkeypatch.setattr(
        enum, "enumerate_domain_controllers",
        lambda _dc, user, _password: (
            [("DC01.EXAMPLE.TEST", "192.0.2.1")] if user == "alice" else []
        ),
    )
    monkeypatch.setattr(enum, "write_results", lambda *_args: None)
    monkeypatch.setattr(util, "ARTEFACTS_DIR", tmp_path / "ad-kit")
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(enum, "export_domain_users", lambda *_args: (2, 1))
    monkeypatch.setattr(enum, "export_domain_computers", lambda *_args: 1)
    monkeypatch.setattr(enum, "print_summary", lambda _data: None)
    monkeypatch.setattr(enum, "print_warning", messages.append)

    enum.run_enumeration()

    session_text = (tmp_path / "ad-kit" / "session.json").read_text(encoding="utf-8")
    session = json.loads(session_text)
    assert len(calls) == 2
    assert session["standard_user_validated"] is True
    assert session["da_validated"] is False
    assert session["domain_users_exported"] is True
    assert session["domain_computers_exported"] is True
    assert session["ntds_dumped"] is False
    assert "secret" not in session_text
    assert any("Continuing enumeration" in message for message in messages)
    assert any("NTDS dump skipped" in message for message in messages)


def test_failed_admin_validation_without_standard_user_stops(monkeypatch):
    prompts = iter(["192.0.2.1", "admin", "secret"])
    confirms = iter([False, True, False, False, False])
    saved = []
    monkeypatch.setattr(enum.typer, "prompt", lambda *_args, **_kwargs: next(prompts))
    monkeypatch.setattr(enum.typer, "confirm", lambda *_args, **_kwargs: next(confirms))
    monkeypatch.setattr(enum, "identify_domain_controller", lambda _dc: ("DC01", "EXAMPLE.TEST"))
    monkeypatch.setattr(enum, "configure_nxc", lambda: None)
    monkeypatch.setattr(enum, "validate_credentials", lambda *_args: (False, False))
    monkeypatch.setattr(enum, "save_session", saved.append)
    monkeypatch.setattr(
        enum, "enumerate_domain_controllers",
        lambda *_args: pytest.fail("Enumeration should stop without a validated account"),
    )
    enum.run_enumeration()
    assert saved == []


def test_scp_retrieval_selects_interface_and_quotes_actual_paths(monkeypatch, tmp_path):
    output = []
    warnings = []
    selections = iter([99, 2])
    files = [tmp_path / "blood hound.zip", tmp_path / "EXAMPLE.TEST.ntds"]
    monkeypatch.setattr(util.getpass, "getuser", lambda: "tester")
    if util.os.name == "posix":
        import pwd

        monkeypatch.setattr(pwd, "getpwuid", lambda _uid: SimpleNamespace(pw_name="tester"))
    monkeypatch.setattr(util, "print_section", lambda *_args: None)
    monkeypatch.setattr(util, "print_info", output.append)
    monkeypatch.setattr(util, "print_warning", warnings.append)
    monkeypatch.setattr(util.console, "print", lambda text="", **_kwargs: output.append(text))
    monkeypatch.setattr(util.typer, "prompt", lambda *_args, **_kwargs: next(selections))
    monkeypatch.setattr(
        util.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout=json.dumps([
            {"ifname": "lo", "flags": ["UP"], "addr_info": [
                {"family": "inet", "local": "127.0.0.1"},
            ]},
            {"ifname": "eth0", "flags": ["UP"], "addr_info": [
                {"family": "inet", "local": "192.0.2.10"},
                {"family": "inet6", "local": "2001:db8::10"},
            ]},
        ])),
    )

    util.generate_scp_command(files)

    command = next(line for line in output if line.startswith("scp "))
    assert shlex.split(command) == [
        "scp", *[f"tester@[2001:db8::10]:{path.resolve()}" for path in files], "./",
    ]
    assert any("eth0: 192.0.2.10" in line for line in output)
    assert any("eth0: 2001:db8::10" in line for line in output)
    assert len(warnings) == 1
    assert "current OS user" in " ".join(output)


def test_scp_retrieval_reports_missing_files_and_interface_errors(monkeypatch, tmp_path):
    warnings = []
    monkeypatch.setattr(util, "print_section", lambda *_args: None)
    monkeypatch.setattr(util, "print_warning", warnings.append)
    monkeypatch.setattr(
        util.subprocess, "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError("ip not found")),
    )
    util.generate_scp_command([])
    util.generate_scp_command([tmp_path / "current.zip"])
    assert "No BloodHound ZIP or NTDS files" in warnings[0]
    assert "Unable to identify network interfaces" in warnings[1]


@pytest.mark.parametrize(
    ("collection_succeeded", "dump_succeeded"),
    [(True, True), (False, True), (True, False)],
)
def test_enumeration_retrieves_only_current_run_files(
    monkeypatch, tmp_path, collection_succeeded, dump_succeeded
):
    prompts = iter(["192.0.2.1", "alice", "secret", "admin", "admin-secret"])
    confirms = iter([True, True, True, True, True])
    output_dir = tmp_path / "ad-kit"
    output_dir.mkdir()
    (output_dir / "old.zip").write_text("stale")
    (output_dir / "OTHER.TEST.ntds").write_text("stale")
    (output_dir / "EXAMPLE.TEST.ntds").write_text("old")
    captured = []
    monkeypatch.setattr(enum.typer, "prompt", lambda *_args, **_kwargs: next(prompts))
    monkeypatch.setattr(enum.typer, "confirm", lambda *_args, **_kwargs: next(confirms))
    monkeypatch.setattr(enum, "identify_domain_controller", lambda _dc: ("DC01", "EXAMPLE.TEST"))
    monkeypatch.setattr(enum, "configure_nxc", lambda: None)
    monkeypatch.setattr(
        enum, "validate_credentials",
        lambda _dc, username, _password: (True, username == "admin"),
    )
    monkeypatch.setattr(
        enum, "enumerate_domain_controllers",
        lambda *_args: [("DC01.EXAMPLE.TEST", "192.0.2.1")],
    )
    monkeypatch.setattr(enum, "write_results", lambda *_args: None)
    monkeypatch.setattr(enum, "save_session", lambda *_args: None)
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(enum, "get_artefacts_dir", lambda: output_dir)
    monkeypatch.setattr(enum, "export_domain_users", lambda *_args: (2, 1))
    monkeypatch.setattr(enum, "export_domain_computers", lambda *_args: 1)
    monkeypatch.setattr(enum, "print_summary", lambda *_args: None)
    monkeypatch.setattr(enum, "generate_scp_command", lambda files: captured.extend(files))

    def collect(*_args):
        (output_dir / "current.zip").write_text("new")
        return collection_succeeded

    def dump(command, **_kwargs):
        (output_dir / "EXAMPLE.TEST.ntds").write_text("fresh ntds")
        return subprocess.CompletedProcess(
            command, 0 if dump_succeeded else 1, stdout="", stderr=""
        )

    monkeypatch.setattr(enum, "run_rusthound", collect)
    monkeypatch.setattr(enum.subprocess, "run", dump)
    enum.run_enumeration()
    expected = []
    if collection_succeeded:
        expected.append(output_dir / "current.zip")
    if dump_succeeded:
        expected.append(output_dir / "EXAMPLE.TEST.ntds")
    assert captured == expected


def test_scp_retrieval_handles_no_usable_interface(monkeypatch, tmp_path):
    warnings = []
    monkeypatch.setattr(util, "print_section", lambda *_args: None)
    monkeypatch.setattr(util, "print_warning", warnings.append)
    monkeypatch.setattr(
        util.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout=json.dumps([
            {"ifname": "lo", "flags": ["UP"], "addr_info": [
                {"family": "inet", "local": "127.0.0.1"},
            ]},
        ])),
    )
    util.generate_scp_command([tmp_path / "current.zip"])
    assert warnings == ["No usable network interface addresses were found."]
