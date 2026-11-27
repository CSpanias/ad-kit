from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from ad_kit.checks import privileged_excessive
from ad_kit.commands import enum
from ad_kit.commands.checks import policy, unauthenticated
from ad_kit.core.exceptions import ADKitError
from ad_kit.core.privileged import PRIVILEGED_GROUPS


@contextmanager
def no_progress(_message):
    yield


@pytest.mark.parametrize("failure", ["exit", "missing"])
def test_user_export_failure_does_not_replace_old_files(monkeypatch, tmp_path, failure):
    old_users = tmp_path / "domain-users.txt"
    old_filtered = tmp_path / "domain-users-filtered.txt"
    old_users.write_text("old-user\n")
    old_filtered.write_text("old-filtered\n")
    monkeypatch.setattr(enum, "get_artefacts_dir", lambda: tmp_path)

    def run(command, **_kwargs):
        assert Path(command[-1]) != old_users
        if failure == "exit":
            Path(command[-1]).write_text("partial\n")
            return SimpleNamespace(returncode=1, stderr="failure secret")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(enum.subprocess, "run", run)
    with pytest.raises(RuntimeError) as error:
        enum.export_domain_users("dc", "user", "secret", set())
    assert "secret" not in str(error.value)
    assert old_users.read_text() == "old-user\n"
    assert old_filtered.read_text() == "old-filtered\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "domain-users-filtered.txt", "domain-users.txt",
    ]


def test_successful_user_export_replaces_files_and_filters(monkeypatch, tmp_path):
    monkeypatch.setattr(enum, "get_artefacts_dir", lambda: tmp_path)
    (tmp_path / "domain-users.txt").write_text("old\n")
    (tmp_path / "domain-users-filtered.txt").write_text("old\n")

    def run(command, **_kwargs):
        Path(command[-1]).write_text("Alice\ntest-user\n")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(enum.subprocess, "run", run)
    assert enum.export_domain_users("dc", "user", "secret", {"test-user"}) == (2, 1)
    assert (tmp_path / "domain-users.txt").read_text().splitlines() == ["Alice", "test-user"]
    assert (tmp_path / "domain-users-filtered.txt").read_text().splitlines() == ["Alice"]


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [(1, ""), (0, ""), (0, "Total records returned: 2\n")],
)
def test_unconfirmed_computer_export_preserves_old_file(monkeypatch, tmp_path, returncode, stdout):
    output = tmp_path / "domain-computers.txt"
    output.write_text("OLD.EXAMPLE.TEST\n")
    monkeypatch.setattr(enum, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        enum.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=returncode, stdout=stdout, stderr="secret" if returncode else ""
        ),
    )
    with pytest.raises(RuntimeError) as error:
        enum.export_domain_computers("example.test", "dc", "user", "secret")
    assert "secret" not in str(error.value)
    assert output.read_text() == "OLD.EXAMPLE.TEST\n"


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [("LDAP dc 389 DC01 HOST01$\n", ["HOST01.EXAMPLE.TEST"]),
     ("Total records returned: 0\n", [])],
)
def test_confirmed_computer_export(monkeypatch, tmp_path, stdout, expected):
    monkeypatch.setattr(enum, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        enum.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=stdout, stderr=""),
    )
    assert enum.export_domain_computers("example.test", "dc", "user", "secret") == len(expected)
    assert (tmp_path / "domain-computers.txt").read_text().splitlines() == expected


def test_computer_export_preserves_old_file_if_replacement_fails(monkeypatch, tmp_path):
    output = tmp_path / "domain-computers.txt"
    output.write_text("OLD.EXAMPLE.TEST\n")
    monkeypatch.setattr(enum, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        enum.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="LDAP dc 389 DC01 HOST01$\n", stderr=""
        ),
    )

    def failed_replace(_path, _target):
        raise OSError("replacement failed")

    monkeypatch.setattr(Path, "replace", failed_replace)
    with pytest.raises(OSError, match="replacement failed"):
        enum.export_domain_computers("example.test", "dc", "user", "secret")
    assert output.read_text() == "OLD.EXAMPLE.TEST\n"


@pytest.mark.parametrize(
    ("runner", "session"),
    [
        (unauthenticated.run_smb_checks, {"domain_computers_exported": False}),
        (policy.run_local_admin_checks, {"domain_computers_exported": False}),
        (unauthenticated.run_asreproast_checks, {"domain_users_exported": False}),
    ],
)
def test_incomplete_inventory_blocks_dependent_checks(monkeypatch, runner, session):
    module = policy if runner == policy.run_local_admin_checks else unauthenticated
    monkeypatch.setattr(module, "require_session", lambda: session)
    with pytest.raises(ADKitError, match="collection was not completed"):
        runner("secret")


def test_user_collection_is_saved_before_computer_failure(monkeypatch):
    prompts = iter(["192.0.2.1", "tester", "secret"])
    confirms = iter([True, False, False, False])
    saved = []
    errors = []
    monkeypatch.setattr(enum.typer, "prompt", lambda *_args, **_kwargs: next(prompts))
    monkeypatch.setattr(enum.typer, "confirm", lambda *_args, **_kwargs: next(confirms))
    monkeypatch.setattr(enum, "identify_domain_controller", lambda _dc: ("DC01", "EXAMPLE.TEST"))
    monkeypatch.setattr(enum, "configure_nxc", lambda: None)
    monkeypatch.setattr(enum, "validate_credentials", lambda *_args: (True, False))
    monkeypatch.setattr(enum, "enumerate_domain_controllers", lambda *_args: [("DC01.EXAMPLE.TEST", "192.0.2.1")])
    monkeypatch.setattr(enum, "write_results", lambda *_args: None)
    monkeypatch.setattr(enum, "save_session", lambda data: saved.append(data.copy()))
    monkeypatch.setattr(enum, "progress", no_progress)
    monkeypatch.setattr(enum, "export_domain_users", lambda *_args: (2, 1))

    def failed_computers(*_args):
        raise RuntimeError("Computer export failed")

    monkeypatch.setattr(enum, "export_domain_computers", failed_computers)
    monkeypatch.setattr(enum, "print_error", errors.append)
    assert enum.run_enumeration() is False
    assert saved[0]["excluded_users"] == ["tester"]
    assert saved[-1]["domain_users_exported"] is True
    assert saved[-1]["domain_users_filtered_count"] == 1
    assert saved[-1]["domain_computers_exported"] is False
    assert errors == ["Computer export failed"]


def test_privileged_check_does_not_read_stale_users(monkeypatch, tmp_path):
    (tmp_path / "domain-users-filtered.txt").write_text("stale\n" * 10)
    monkeypatch.setattr(privileged_excessive, "require_session", lambda: {
        "domain_users_exported": False, "domain_users_filtered_count": 10,
    })
    monkeypatch.setattr(
        privileged_excessive, "get_privileged_group_members",
        lambda *_args: {group: [] for group in PRIVILEGED_GROUPS},
    )
    commands = []

    def run(name, _command, **_kwargs):
        commands.append(name)
        if name == "privileged-enabled-users":
            return (
                "LDAP dc 389 DC [+] Response for object: CN=fresh,DC=example\n"
                "LDAP dc 389 DC sAMAccountName       fresh\n"
            )
        pytest.fail(f"Unexpected command: {name}")

    monkeypatch.setattr(privileged_excessive, "run_check", run)
    result, _ = privileged_excessive.privileged_excessive_check("dc", "user", "secret")
    assert result["enabled_users"] == 1
    assert commands == ["privileged-enabled-users"]
