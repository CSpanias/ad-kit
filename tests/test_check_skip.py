from ad_kit.commands import check
from ad_kit.core.exceptions import CheckExecutionError


def test_selected_checks_skip_failed_check_and_continue(monkeypatch):
    printed = []
    calls = []

    monkeypatch.setattr(check, "print_error", lambda message: printed.append(message))

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

    check.run_selected_checks(["ldap", "smb"])

    assert calls == ["passing", "failing"]
    assert len(printed) == 1
    assert "Skipped 'smb'" in printed[0]
    assert "unrecognized arguments" in printed[0]