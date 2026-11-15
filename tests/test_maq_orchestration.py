from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from rich.console import Console
from rich.table import Table

from ad_kit.commands.checks import policy


@pytest.mark.parametrize(
    ("quota", "color_code"),
    [
        ("2", "31"),
        ("0", "32"),
    ],
)
def test_maq_quota_value_color(
    monkeypatch,
    tmp_path,
    quota,
    color_code,
):
    results = {
        "machine_account_quota": quota,
        "machine_join_group": "Authenticated Users",
        "machine_created": False,
        "machine_authenticated": False,
        "machine_deleted": False,
        "cleanup_method": "None",
        "machine_name": "ADKIT-TEST",
        "machine_password": "test-password",
    }
    printed = []

    @contextmanager
    def fake_progress(_message):
        yield

    def fake_print(*args, **kwargs):
        printed.append(args)

    monkeypatch.setattr(policy, "require_session", lambda: {
        "dc_ip": "192.0.2.1",
        "standard_user": "test-user",
    })
    monkeypatch.setattr(policy, "progress", fake_progress)
    monkeypatch.setattr(policy, "maq_check", lambda *_args: results)
    monkeypatch.setattr(policy, "load_finding", lambda *_args: SimpleNamespace(evidence=[]))
    monkeypatch.setattr(policy, "write_markdown_report", lambda *_args: None)
    monkeypatch.setattr(policy, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(policy.console, "print", fake_print)

    policy.run_maq_checks("test-password")

    tables = [args[0] for args in printed if args and isinstance(args[0], Table)]
    rendered = Console(
        record=True,
        force_terminal=True,
        color_system="standard",
    )
    rendered.print(tables[0])

    assert f"\x1b[{color_code}m{quota}\x1b[0m" in rendered.export_text(styles=True)
