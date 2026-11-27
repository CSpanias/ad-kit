import json
import shlex
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from ad_kit.commands import enum
from ad_kit.core import util


NTDS_RECORD = (
    "example.test\\alice:1105:aad3b435b51404eeaad3b435b51404ee:"
    "0123456789abcdef0123456789abcdef::: (status=Enabled)\n"
)


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
    assert session["dc_controllers"] == [{"hostname": "DC01.EXAMPLE.TEST", "ip": "192.0.2.1"}]
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
    captured, sessions, attempted_dcs = [], [], []
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
        lambda *_args: [("DC02.EXAMPLE.TEST", "192.0.2.2"), ("DC01.EXAMPLE.TEST", "192.0.2.1")],
    )
    monkeypatch.setattr(enum, "write_results", lambda *_args: None)
    monkeypatch.setattr(enum, "save_session", lambda data: sessions.append(data.copy()))
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(enum, "get_artefacts_dir", lambda: output_dir)
    monkeypatch.setattr(enum, "export_domain_users", lambda *_args: (2, 1))
    monkeypatch.setattr(enum, "export_domain_computers", lambda *_args: 1)
    monkeypatch.setattr(enum, "print_summary", lambda *_args: None)
    monkeypatch.setattr(enum, "generate_scp_command", lambda files: captured.extend(files))

    def collect(*_args):
        (output_dir / "current.zip").write_text("new")
        return collection_succeeded

    def dump(command, **kwargs):
        attempted_dcs.append(command[1].rsplit("@", 1)[-1])
        (kwargs["cwd"] / "EXAMPLE.TEST.ntds").write_text(NTDS_RECORD)
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
    assert sessions[-1]["ntds_attempted"] is True
    assert sessions[-1]["dc_controllers"] == [
        {"hostname": "DC02.EXAMPLE.TEST", "ip": "192.0.2.2"},
        {"hostname": "DC01.EXAMPLE.TEST", "ip": "192.0.2.1"},
    ]
    assert sessions[-1]["ntds_dumped"] is dump_succeeded
    assert attempted_dcs == (["192.0.2.1"] if dump_succeeded else ["192.0.2.1", "192.0.2.2"])
    if dump_succeeded:
        assert sessions[-1]["ntds_dc"] == "192.0.2.1"


@pytest.mark.parametrize("first_failure", ["missing", "partial"])
def test_ntds_failover_discards_partial_output_and_preserves_success(monkeypatch, tmp_path, first_failure):
    calls = []
    warnings = []
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(enum, "print_warning", warnings.append)
    old_dump = tmp_path / "EXAMPLE.TEST.ntds"
    old_dump.write_text("previous")

    def run(command, **kwargs):
        calls.append(command[1].rsplit("@", 1)[-1])
        dump = kwargs["cwd"] / "EXAMPLE.TEST.ntds"
        if len(calls) == 1:
            if first_failure == "partial":
                dump.write_text(NTDS_RECORD)
            return subprocess.CompletedProcess(
                command, 0,
                stdout="[-] Error while processing user!\n" if first_failure == "partial" else "",
                stderr="",
            )
        dump.write_text(NTDS_RECORD)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(enum.subprocess, "run", run)
    result = enum._dump_ntds(
        "EXAMPLE.TEST", "admin", "secret", ["192.0.2.1", "192.0.2.1", "192.0.2.2"], tmp_path,
    )
    assert result == (old_dump, "192.0.2.2")
    assert calls == ["192.0.2.1", "192.0.2.2"]
    assert old_dump.read_text() == NTDS_RECORD
    assert any(
        "processing user" in warning if first_failure == "partial"
        else "No valid NTDS" in warning
        for warning in warnings
    )
    assert list(tmp_path.iterdir()) == [old_dump]


@pytest.mark.parametrize(
    "failure", ["missing", "empty", "invalid", "encoding", "resume", "nonzero", "warning"],
)
def test_ntds_rejects_failed_or_incomplete_attempts(monkeypatch, tmp_path, failure):
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    warnings = []
    monkeypatch.setattr(enum, "print_warning", warnings.append)
    old_dump = tmp_path / "EXAMPLE.TEST.ntds"
    old_dump.write_text("previous")

    def run(command, **kwargs):
        directory = kwargs["cwd"]
        if failure != "missing":
            content = "" if failure == "empty" else "not a hash\n" if failure == "invalid" else NTDS_RECORD
            (directory / "EXAMPLE.TEST.ntds").write_text(content)
        if failure == "encoding":
            (directory / "EXAMPLE.TEST.ntds").write_bytes(b"\xff")
        if failure == "resume":
            (directory / "sessionresume_test").write_text("partial")
        return subprocess.CompletedProcess(
            command, 1 if failure == "nonzero" else 0,
            stdout="[!] DRSCrackNames returned 0 items, skipping\n" if failure == "warning" else "",
            stderr="",
        )

    monkeypatch.setattr(enum.subprocess, "run", run)
    assert enum._dump_ntds("EXAMPLE.TEST", "admin", "secret", ["192.0.2.1"], tmp_path) is None
    assert old_dump.read_text() == "previous"
    assert warnings
    assert list(tmp_path.iterdir()) == [old_dump]


def test_ntds_authentication_failure_stops_retry_and_redacts_secrets(monkeypatch, tmp_path):
    calls, warnings, errors = [], [], []
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(enum, "print_warning", warnings.append)
    monkeypatch.setattr(enum, "print_error", errors.append)

    def run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command, 0, stdout="[-] STATUS_LOGON_FAILURE secret 0123456789abcdef0123456789abcdef\n",
            stderr="",
        )

    monkeypatch.setattr(enum.subprocess, "run", run)
    assert enum._dump_ntds(
        "EXAMPLE.TEST", "admin", "secret", ["192.0.2.1", "192.0.2.2"], tmp_path,
    ) is None
    assert len(calls) == 1
    assert "secret" not in " ".join(warnings)
    assert "0123456789abcdef0123456789abcdef" not in " ".join(warnings)
    assert any("not trying additional DCs" in error for error in errors)


def test_ntds_reports_debug_only_early_failure_and_retries_other_dc(monkeypatch, tmp_path):
    calls, warnings = [], []
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(enum, "print_warning", warnings.append)

    def run(command, **kwargs):
        calls.append(command[1].rsplit("@", 1)[-1])
        assert "-debug" in command
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command, 0,
                stdout=(
                    "[+] Impacket Library Installation Path: /sensitive/path\n"
                    "[+] Exiting NTDSHashes.dump() because SMB SessionError: "
                    "STATUS_ACCESS_DENIED secret 0123456789abcdef0123456789abcdef\n"
                    "[*] Cleaning up...\n"
                ),
                stderr="",
            )
        (kwargs["cwd"] / "EXAMPLE.TEST.ntds").write_text(NTDS_RECORD)
        return subprocess.CompletedProcess(
            command, 0, stdout="[+] Routine debug details\n" + NTDS_RECORD, stderr="",
        )

    monkeypatch.setattr(enum.subprocess, "run", run)
    result = enum._dump_ntds(
        "EXAMPLE.TEST", "admin", "secret", ["192.0.2.1", "192.0.2.2"], tmp_path,
    )
    assert result == (tmp_path / "EXAMPLE.TEST.ntds", "192.0.2.2")
    assert calls == ["192.0.2.1", "192.0.2.2"]
    assert any("Preliminary NTDS check failed: SMB SessionError: STATUS_ACCESS_DENIED" in warning
               for warning in warnings)
    assert "secret" not in " ".join(warnings)
    assert "0123456789abcdef0123456789abcdef" not in " ".join(warnings)
    assert "/sensitive/path" not in " ".join(warnings)
    assert "No valid NTDS" not in " ".join(warnings)


def test_ntds_debug_authentication_failure_stops_retry(monkeypatch, tmp_path):
    calls, warnings, errors = [], [], []
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(enum, "print_warning", warnings.append)
    monkeypatch.setattr(enum, "print_error", errors.append)

    def run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command, 0,
            stdout="[+] Exiting NTDSHashes.dump() because STATUS_ACCOUNT_LOCKED_OUT\n",
            stderr="",
        )

    monkeypatch.setattr(enum.subprocess, "run", run)
    assert enum._dump_ntds(
        "EXAMPLE.TEST", "admin", "secret", ["192.0.2.1", "192.0.2.2"], tmp_path,
    ) is None
    assert len(calls) == 1
    assert any("STATUS_ACCOUNT_LOCKED_OUT" in warning for warning in warnings)
    assert any("not trying additional DCs" in error for error in errors)


def test_missing_secretsdump_is_reported_without_retry(monkeypatch, tmp_path):
    calls, errors = [], []
    monkeypatch.setattr(enum, "progress", lambda _message: nullcontext())
    monkeypatch.setattr(enum, "print_error", errors.append)

    def run(*_args, **_kwargs):
        calls.append(True)
        raise FileNotFoundError("secretsdump.py not found")

    monkeypatch.setattr(enum.subprocess, "run", run)
    assert enum._dump_ntds(
        "EXAMPLE.TEST", "admin", "secret", ["192.0.2.1", "192.0.2.2"], tmp_path,
    ) is None
    assert len(calls) == 1
    assert "secretsdump.py not found" in errors[0]


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
