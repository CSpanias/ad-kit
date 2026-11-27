import pytest
from typer.testing import CliRunner

from ad_kit.cli import app
from ad_kit.commands import check
from ad_kit.core.exceptions import CheckExecutionError


def test_selected_checks_skip_failed_check_and_continue(monkeypatch, tmp_path):
    printed = []
    calls = []

    monkeypatch.setattr(check, "print_error", lambda message: printed.append(message))
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)

    def passing(std_pass=None):
        calls.append("passing")
        return std_pass

    def failing(std_pass=None):
        calls.append("failing")
        raise CheckExecutionError(
            "smb",
            ["nxc", "smb", "dc"],
            returncode=2,
            stderr="nxc: error: unrecognized arguments: --smb-fake-flag",
        )

    monkeypatch.setattr(check, "run_ldap_checks", passing)
    monkeypatch.setattr(check, "run_smb_checks", failing)

    assert check.run_selected_checks(["ldap", "smb"]) is False

    assert calls == ["passing", "failing"]
    assert len(printed) == 1
    assert "Skipped 'smb'" in printed[0]
    assert "unrecognized arguments" in printed[0]


def test_failed_check_returns_nonzero_after_writing_report(monkeypatch, tmp_path):
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        check, "run_ldap_checks",
        lambda: (_ for _ in ()).throw(CheckExecutionError("ldap", [], stderr="unavailable")),
    )
    result = CliRunner().invoke(app, ["check", "ldap"])
    assert result.exit_code != 0
    assert (tmp_path / "ad-kit_findings_ldap.html").exists()
    assert "unavailable" in (tmp_path / "ad-kit_findings_ldap.html").read_text(encoding="utf-8")


def test_missing_authentication_does_not_prevent_other_selected_checks(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        check, "authenticate_standard_user",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("session unavailable")),
    )
    monkeypatch.setattr(check, "run_ldap_checks", lambda: calls.append("ldap"))
    monkeypatch.setattr(check, "run_dns_checks", lambda _password: pytest.fail("dns ran"))
    assert check.run_selected_checks(["dns", "ldap", "pass-pol"]) is False
    assert calls == ["ldap"]
    report = (tmp_path / "ad-kit_findings_dns_ldap_pass-pol.html").read_text(encoding="utf-8")
    assert "session unavailable" in report


def test_missing_inventory_does_not_prevent_other_checks(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        check, "run_smb_checks",
        lambda _password: (_ for _ in ()).throw(FileNotFoundError("missing inventory")),
    )
    monkeypatch.setattr(check, "run_ldap_checks", lambda: calls.append("ldap"))
    assert check.run_selected_checks(["smb", "ldap"]) is False
    assert calls == ["ldap"]
    assert "missing inventory" in (tmp_path / "ad-kit_findings_smb_ldap.html").read_text(
        encoding="utf-8"
    )