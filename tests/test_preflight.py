import json

import pytest
from typer.testing import CliRunner

from ad_kit import cli
from ad_kit.commands import check, enum
from ad_kit.core import preflight


def test_preflight_reports_only_selected_missing_tools_and_inventory(monkeypatch, tmp_path):
    warnings = []
    seen = []
    monkeypatch.setattr(preflight, "ARTEFACTS_DIR", tmp_path)
    monkeypatch.setattr(preflight, "print_warning", warnings.append)
    monkeypatch.setattr(preflight, "which", lambda command: seen.append(command) or None)
    (tmp_path / "session.json").write_text(json.dumps({
        "domain_users_exported": True,
        "domain_computers_exported": False,
    }))

    preflight.check_preflight(["smb", "dns"])

    assert set(seen) == {"nxc", "bloodyAD"}
    assert any("ad-kit tools install netexec" in warning for warning in warnings)
    assert any("ad-kit tools install bloodyad" in warning for warning in warnings)
    assert any("domain-computers.txt" in warning for warning in warnings)
    assert any("Domain computer collection is incomplete" in warning for warning in warnings)
    assert not any("domain-users-filtered.txt" in warning for warning in warnings)


def test_enum_preflight_checks_only_selected_optional_tools(monkeypatch):
    seen = []
    monkeypatch.setattr(preflight, "which", lambda command: seen.append(command) or command)
    preflight.enum_preflight(collect=False, dump_ntds=True, retrieval=False)
    assert "nxc" in seen and "secretsdump.py" in seen
    assert "rusthound-ce" not in seen and "ip" not in seen


@pytest.mark.parametrize("contents", ["[]", "{invalid json"])
def test_invalid_session_is_advisory(monkeypatch, tmp_path, contents):
    warnings = []
    monkeypatch.setattr(preflight, "ARTEFACTS_DIR", tmp_path)
    monkeypatch.setattr(preflight, "which", lambda command: command)
    monkeypatch.setattr(preflight, "print_warning", warnings.append)
    (tmp_path / "session.json").write_text(contents)
    preflight.check_preflight(["smb"])
    assert any("Cannot read assessment session" in warning for warning in warnings)


@pytest.mark.parametrize(("answer", "expected"), [("n\n", 1), ("y\n", 0)])
def test_impact_confirmation_gates_selected_checks(monkeypatch, answer, expected):
    calls = []
    monkeypatch.setattr(cli, "check_preflight", lambda modules: calls.append(("preflight", modules)))
    monkeypatch.setattr(check, "run_selected_checks", lambda modules: calls.append(("run", modules)) or True)
    result = CliRunner().invoke(cli.app, ["check", "ldap", "dns"], input=answer)
    assert result.exit_code == expected
    assert "temporary DNS record" in result.output
    assert "manual removal" in result.output
    if expected:
        assert result.output.count("Assessment cancelled.") == 1
    assert calls == ([("preflight", ["ldap", "dns"])] + (
        [("run", ["ldap", "dns"])] if expected == 0 else []
    ))


def test_read_only_selection_does_not_prompt_or_include_excluded_impact(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "check_preflight", lambda modules: calls.append(modules))
    monkeypatch.setattr(check, "run_selected_checks", lambda modules: calls.append(modules) or True)
    result = CliRunner().invoke(cli.app, ["check", "ldap", "dns", "--exclude", "dns"])
    assert result.exit_code == 0, result.output
    assert "temporary DNS record" not in result.output
    assert "Continue with these checks?" not in result.output
    assert calls == [["ldap"], ["ldap"]]


def test_declining_ntds_impact_cancels_before_domain_discovery(monkeypatch):
    prompts = iter(["192.0.2.1", "alice", "secret", "admin", "admin-secret"])
    confirms = iter([True, True, False, True, False, False])
    monkeypatch.setattr(enum.typer, "prompt", lambda *_args, **_kwargs: next(prompts))
    monkeypatch.setattr(enum.typer, "confirm", lambda *_args, **_kwargs: next(confirms))
    monkeypatch.setattr(enum, "enum_preflight", lambda **_kwargs: None)
    monkeypatch.setattr(
        enum, "identify_domain_controller", lambda _dc: pytest.fail("domain discovery ran")
    )
    assert enum.run_enumeration() is False
