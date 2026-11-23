import io
from contextlib import nullcontext

import pytest
from rich.console import Console

from ad_kit.checks import dcsync
from ad_kit.commands.checks import privileged
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


def test_saved_expected_sids_are_validated():
    assert privileged._expected_dcsync_sids(
        {"expected_dcsync_sids": [f"{DOMAIN_SID.lower()}-1001"]}
    ) == {f"{DOMAIN_SID}-1001"}
    with pytest.raises(ADKitError, match="Invalid expected DCSync SID"):
        privileged._expected_dcsync_sids({"expected_dcsync_sids": ["MSOL_example"]})


def test_no_finding_when_all_trustees_are_excluded():
    assert dcsync.dcsync_findings([]) == []


@pytest.mark.parametrize("unknown_count", [0, 1, 2])
@pytest.mark.parametrize("cisco_complete", [False, True])
@pytest.mark.parametrize("include_resolved", [False, True])
def test_dcsync_output_and_findings(monkeypatch, unknown_count, cisco_complete, include_resolved):
    output = io.StringIO()
    findings = []
    session = {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
        "expected_dcsync_sids": [
            f"{DOMAIN_SID}-1001", f"{DOMAIN_SID}-1006", f"{DOMAIN_SID}-1010",
        ],
    }
    trustees = [
        {
            "name": "expected", "sid": f"{DOMAIN_SID}-1001",
            "rights": ["right"], "complete": True,
        },
        {"name": "partial", "sid": f"{DOMAIN_SID}-1003", "rights": ["right"], "complete": False},
        {"name": "EXAMPLE\\mSoL_connector", "sid": f"{DOMAIN_SID}-1004",
         "rights": ["right"], "complete": True},
        {"name": "Cisco_Connector", "sid": f"{DOMAIN_SID}-1006",
         "rights": ["right"], "complete": cisco_complete},
        {"name": "UNKNOWN", "sid": f"{DOMAIN_SID}-1007", "rights": ["right"], "complete": False},
    ]
    if include_resolved:
        trustees.extend([
            {"name": "unexpected", "sid": f"{DOMAIN_SID}-1002",
             "rights": ["right"], "complete": True},
            {"name": "msolother", "sid": f"{DOMAIN_SID}-1005",
             "rights": ["right"], "complete": True},
        ])
    trustees.extend(
        {"name": "UNKNOWN", "sid": f"{DOMAIN_SID}-{1010 + i}",
         "rights": ["right"], "complete": True}
        for i in range(unknown_count)
    )
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda *_args: None)
    monkeypatch.setattr(privileged, "print_info", lambda message: print(message, file=output))
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
    privileged.run_privileged_group_checks("pw")
    text = output.getvalue()
    assert f"{DOMAIN_SID}-1001" not in text
    assert (f"{DOMAIN_SID}-1002" in text) is include_resolved
    assert "partial" not in text
    assert "mSoL_connector" not in text
    assert ("msolother" in text) is include_resolved
    assert ("Cisco_Connector" in text) is cisco_complete
    assert "Select confirmed expected" not in text
    assert ("UNKNOWN" in text) is (unknown_count > 0)
    assert f"{DOMAIN_SID}-1007" not in text
    for i in range(unknown_count):
        assert f"{DOMAIN_SID}-{1010 + i}" in text
    total = 2 * int(include_resolved) + unknown_count + int(cisco_complete)
    assert ("No unexpected trustees found" in text) is (total == 0)
    assert "unresolved trustee" not in text
    if total:
        finding = next(finding for finding in findings if finding.id == "PRIV-005")
        assert len(finding.evidence) == total
        assert sum("UNKNOWN" in item for item in finding.evidence) == unknown_count
        assert any("Cisco_Connector" in item for item in finding.evidence) is cisco_complete
        assert all("mSoL_connector" not in item and "partial" not in item
                   for item in finding.evidence)
    else:
        assert not findings
