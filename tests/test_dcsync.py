import io
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from rich.console import Console

from ad_kit.checks import dcsync
from ad_kit.commands.checks import privileged
from ad_kit.core import util
from ad_kit.core.exceptions import ADKitError

DOMAIN_SID = "S-1-5-21-1-2-3"
RIGHTS = dcsync.DCSYNC_RIGHTS


def _ace(
    index: int,
    guid: str,
    trustee: str,
    sid: str,
) -> str:
    return f"""[*] ACE[{index}] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     Access mask               : ControlAccess (0x100)
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : {RIGHTS[guid]} ({guid})
[*]     Trustee (SID)             : {trustee} ({sid})
"""


def test_dcsync_check_reports_unexpected_trustees_and_excludes_defaults(
    monkeypatch,
):
    aces = [
        (0, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "MARA_DANIEL", f"{DOMAIN_SID}-2806"),
        (1, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "MARA_DANIEL", f"{DOMAIN_SID}-2806"),
        (2, "89e95b76-444d-4c62-991a-0facbeda640c", "MARA_DANIEL", f"{DOMAIN_SID}-2806"),
        (3, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "DOMAIN ADMINS", f"{DOMAIN_SID}-512"),
        (4, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "ENTERPRISE ADMINS", f"{DOMAIN_SID}-519"),
        (5, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "DOMAIN CONTROLLERS", f"{DOMAIN_SID}-516"),
        (6, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "ENTERPRISE DOMAIN CONTROLLERS", "S-1-5-9"),
        (7, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "MARA_DA", f"{DOMAIN_SID}-2807"),
        (8, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "DC01$", f"{DOMAIN_SID}-1001"),
        (9, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "PARTIAL_USER", f"{DOMAIN_SID}-2808"),
    ]
    outputs = iter(
        [
            f"LDAP 192.0.2.1 Domain SID: {DOMAIN_SID}",
            "".join(
                _ace(index, guid, name, sid)
                for index, guid, name, sid in aces
            ),
        ]
    )
    commands = []

    def fake_run_check(name, command, sensitive_values):
        commands.append((name, command, sensitive_values))
        return next(outputs)

    monkeypatch.setattr(dcsync, "run_check", fake_run_check)

    trustees = dcsync.dcsync_check(
        "192.0.2.1",
        "example.test",
        "poppy",
        "Password123!",
        {"MARA_DA"},
        ["DC01.example.test"],
    )

    assert [trustee["name"] for trustee in trustees] == [
        "MARA_DANIEL",
        "PARTIAL_USER",
    ]
    assert trustees[0]["complete"] is True
    assert trustees[1]["complete"] is False
    findings = dcsync.dcsync_findings(trustees)
    assert [finding.id for finding in findings] == ["PRIV-005"]
    assert "MARA_DANIEL" in findings[0].evidence[0]
    assert commands[0][1][-1] == "--get-sid"
    assert commands[1][1][commands[1][1].index("-target-sid") + 1] == DOMAIN_SID
    assert commands[1][1][-1] == "example.test/poppy:Password123!"
    assert commands[1][2] == [
        "Password123!",
        "example.test/poppy:Password123!",
    ]


def test_expected_trustee_selection_is_saved_by_sid_and_can_be_edited(monkeypatch):
    session = {"domain": "example.test"}
    trustees = [
        {
            "name": "service", "sid": f"{DOMAIN_SID}-1001",
            "rights": ["right"], "complete": True,
        },
        {"name": "other", "sid": f"{DOMAIN_SID}-1002", "rights": ["right"], "complete": True},
        {"name": "partial", "sid": f"{DOMAIN_SID}-1003", "rights": ["right"], "complete": False},
        {"name": "EXAMPLE\\msol_connector", "sid": f"{DOMAIN_SID}-1004",
         "rights": ["right"], "complete": True},
    ]
    saved = []
    choices_seen = []
    selected = [f"{DOMAIN_SID}-1001"]
    monkeypatch.setattr(privileged.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(privileged, "save_session", lambda data: saved.append(dict(data)))

    def checkbox(_message, *, choices):
        choices_seen.append(choices)
        return SimpleNamespace(ask=lambda: selected.copy())

    monkeypatch.setattr(privileged.questionary, "checkbox", checkbox)
    assert privileged._expected_dcsync_sids(session, trustees) == {f"{DOMAIN_SID}-1001"}
    assert saved[-1]["expected_dcsync_sids"] == [f"{DOMAIN_SID}-1001"]
    assert [choice.value for choice in choices_seen[0]] == [
        f"{DOMAIN_SID}-1001", f"{DOMAIN_SID}-1002",
    ]
    assert all(not choice.checked for choice in choices_seen[0])

    selected.clear()
    assert privileged._expected_dcsync_sids(session, trustees) == set()
    assert choices_seen[1][0].checked and not choices_seen[1][1].checked
    assert saved[-1]["expected_dcsync_sids"] == []


def test_hidden_selected_sids_remain_saved_without_appearing_in_prompt(monkeypatch):
    session = {"expected_dcsync_sids": [f"{DOMAIN_SID}-1001", f"{DOMAIN_SID}-1002"]}
    trustees = [
        {"name": "partial", "sid": f"{DOMAIN_SID}-1001", "rights": [], "complete": False},
        {"name": "MSOL_service", "sid": f"{DOMAIN_SID}-1002", "rights": [], "complete": True},
        {"name": "review", "sid": f"{DOMAIN_SID}-1003", "rights": [], "complete": True},
    ]
    choices_seen = []
    monkeypatch.setattr(privileged.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(privileged, "save_session", lambda *_args: None)

    def checkbox(_message, *, choices):
        choices_seen.extend(choices)
        return SimpleNamespace(ask=lambda: [])

    monkeypatch.setattr(privileged.questionary, "checkbox", checkbox)
    assert privileged._expected_dcsync_sids(session, trustees) == {
        f"{DOMAIN_SID}-1001", f"{DOMAIN_SID}-1002",
    }
    assert [choice.value for choice in choices_seen] == [f"{DOMAIN_SID}-1003"]
    assert session["expected_dcsync_sids"] == [f"{DOMAIN_SID}-1001", f"{DOMAIN_SID}-1002"]


def test_expected_sids_apply_noninteractively_and_invalid_state_is_rejected(monkeypatch):
    monkeypatch.setattr(privileged.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert privileged._expected_dcsync_sids(
        {"expected_dcsync_sids": [f"{DOMAIN_SID.lower()}-1001"]}, []
    ) == {f"{DOMAIN_SID}-1001"}
    with pytest.raises(ADKitError, match="Invalid expected DCSync SID"):
        privileged._expected_dcsync_sids({"expected_dcsync_sids": ["MSOL_example"]}, [])


def test_selection_persists_in_assessment_session(monkeypatch, tmp_path):
    session = {"domain": "example.test"}
    trustee = {
        "name": "service", "sid": f"{DOMAIN_SID}-1001",
        "rights": ["right"], "complete": True,
    }
    monkeypatch.setattr(util, "ARTEFACTS_DIR", tmp_path)
    monkeypatch.setattr(privileged.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(
        privileged.questionary, "checkbox",
        lambda *_args, **_kwargs: SimpleNamespace(ask=lambda: [trustee["sid"]]),
    )
    privileged._expected_dcsync_sids(session, [trustee])
    assert util.load_session()["expected_dcsync_sids"] == [trustee["sid"]]
    monkeypatch.setattr(privileged.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert privileged._expected_dcsync_sids(util.load_session(), [trustee]) == {trustee["sid"]}


def test_no_finding_when_all_trustees_are_excluded():
    assert dcsync.dcsync_findings([]) == []


def test_selected_sid_is_excluded_from_table_and_finding(monkeypatch):
    output = io.StringIO()
    findings = []
    session = {"dc_ip": "dc", "domain": "example.test", "standard_user": "user"}
    trustees = [
        {
            "name": "expected", "sid": f"{DOMAIN_SID}-1001",
            "rights": ["right"], "complete": True,
        },
        {"name": "unexpected", "sid": f"{DOMAIN_SID}-1002", "rights": ["right"], "complete": True},
        {"name": "partial", "sid": f"{DOMAIN_SID}-1003", "rights": ["right"], "complete": False},
        {"name": "EXAMPLE\\mSoL_connector", "sid": f"{DOMAIN_SID}-1004",
         "rights": ["right"], "complete": True},
        {"name": "msolother", "sid": f"{DOMAIN_SID}-1005", "rights": ["right"], "complete": True},
    ]
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda *_args: None)
    monkeypatch.setattr(privileged, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(privileged, "record_findings", findings.extend)
    monkeypatch.setattr(privileged, "require_session", lambda: session)
    monkeypatch.setattr(privileged, "privileged_excessive_check", lambda *_args: ({
        "groups": {
            "Domain Admins": {"member_count": 0, "percentage": 0.0, "members": []},
            "Enterprise Admins": {"member_count": 0, "percentage": 0.0, "members": []},
        },
        "admin_count": {"member_count": 0, "percentage": 0.0, "members": []},
    }, []))
    monkeypatch.setattr(privileged, "builtin_accounts_check", lambda *_args: ({
        "administrator": {"enabled": False, "account_name": "administrator"},
        "guest": {"enabled": False, "account_name": "guest"},
    }, []))
    monkeypatch.setattr(privileged, "load_dc_hostnames", lambda: [])
    monkeypatch.setattr(privileged, "dcsync_check", lambda *_args: trustees)
    monkeypatch.setattr(
        privileged, "_expected_dcsync_sids", lambda *_args: {f"{DOMAIN_SID}-1001"}
    )

    privileged.run_privileged_group_checks("pw")
    assert f"{DOMAIN_SID}-1001" not in output.getvalue()
    assert "unexpected" in output.getvalue()
    assert "partial" not in output.getvalue()
    assert "mSoL_connector" not in output.getvalue()
    assert "msolother" in output.getvalue()
    finding = next(finding for finding in findings if finding.id == "PRIV-005")
    assert len(finding.evidence) == 2
    assert "unexpected" in finding.evidence[0]
    assert "msolother" in finding.evidence[1]
    assert all("mSoL_connector" not in item and "partial" not in item for item in finding.evidence)
