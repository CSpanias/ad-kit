import io
from contextlib import nullcontext

import pytest
from rich.console import Console

from ad_kit.checks import dcsync
from ad_kit.commands.checks import privileged
from ad_kit.core.exceptions import ADKitError
from ad_kit.reporting.html import render_html
from ad_kit.reporting.markdown import format_finding_sections

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


def _full_control_ace(index, name, sid, mask, *, ace_type="ACCESS_ALLOWED_ACE",
                      ace_flags="None", object_type=""):
    return f"""[*] ACE[{index}] info
[*]     ACE Type                  : {ace_type}
[*]     ACE flags                 : {ace_flags}
[*]     Access mask               : FullControl ({mask})
{object_type}[*]     Trustee (SID)             : {name} ({sid})
"""


def test_dcsync_detects_domain_generic_all_and_ignores_scoped_or_inapplicable_aces():
    first = f"{DOMAIN_SID}-2001"
    second = f"{DOMAIN_SID}-2002"
    output = "".join([
        _full_control_ace(0, "mapped", first, "0xf01ff"),
        _full_control_ace(1, "generic", second, "0x10000000"),
        _full_control_ace(2, "denied", f"{DOMAIN_SID}-2003", "0xf01ff",
                          ace_type="ACCESS_DENIED_ACE"),
        _full_control_ace(3, "inherit_only", f"{DOMAIN_SID}-2004", "0xf01ff",
                          ace_flags="INHERIT_ONLY_ACE"),
        _full_control_ace(
            4, "scoped", f"{DOMAIN_SID}-2005", "0xf01ff",
            ace_type="ACCESS_ALLOWED_OBJECT_ACE",
            object_type=(
                "[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT\n"
                "[*]     Object type (GUID)        : Other (11111111-1111-1111-1111-111111111111)\n"
            ),
        ),
        _full_control_ace(5, "partial_mask", f"{DOMAIN_SID}-2006", "0x100"),
        _ace(6, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "mapped", first),
        _ace(7, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "wrong_mask", second)
        .replace("ControlAccess (0x100)", "ReadProperty (0x10)"),
    ])
    trustees = dcsync._parse_dcsync_aces(output)
    assert [trustee["name"] for trustee in trustees] == ["generic", "mapped"]
    assert all(trustee["complete"] for trustee in trustees)
    assert trustees[0]["rights"] == ["GenericAll"]
    assert trustees[1]["rights"] == ["GenericAll", "DS-Replication-Get-Changes"]

    finding = dcsync.dcsync_findings(trustees)[0]
    assert "GenericAll grants full control over the domain object" in finding.commentary
    assert "Review GenericAll permissions" in finding.remediation
    assert "GenericAll on the domain naming context" in finding.evidence_introduction
    assert finding.evidence == [
        f"`generic` ({second}) - GenericAll",
        f"`mapped` ({first}) - GenericAll",
    ]


def test_dcsync_distinguishes_generic_all_from_explicit_replication_rights():
    user_sid = f"{DOMAIN_SID}-2010"
    trustees = dcsync._parse_dcsync_aces(
        _full_control_ace(0, "full", f"{DOMAIN_SID}-2000", "0xf01ff")
        + _ace(1, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "replicator", user_sid)
        + _ace(2, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "replicator", user_sid)
    )
    finding = dcsync.dcsync_findings(trustees)[0]
    assert finding.evidence == [
        f"`full` ({DOMAIN_SID}-2000) - GenericAll",
        f"`replicator` ({user_sid}) - explicit core DCSync rights",
    ]
    trustees = dcsync._parse_dcsync_aces(
        _full_control_ace(0, "replicator", user_sid, "0xf01ff")
        + _ace(1, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "replicator", user_sid)
        + _ace(2, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "replicator", user_sid)
    )
    assert dcsync.dcsync_findings(trustees)[0].evidence == [
        f"`replicator` ({user_sid}) - GenericAll; explicit core DCSync rights",
    ]


def test_dcsync_checks_full_domain_dacl_and_excludes_default_generic_all(monkeypatch):
    domain_admin = f"{DOMAIN_SID}-512"
    user_sid = f"{DOMAIN_SID}-2000"
    output = (
        _full_control_ace(0, "DOMAIN ADMINS", domain_admin, "0xf01ff")
        + _full_control_ace(
            1, "operator", user_sid, "0x10000000",
            ace_type="ACCESS_ALLOWED_OBJECT_ACE", ace_flags="INHERITED_ACE",
            object_type="[*]     Flags                     : None\n",
        )
    )
    calls = []

    def run(name, command, sensitive_values):
        calls.append((name, command))
        return f"Domain SID: {DOMAIN_SID}" if name == "dcsync-domain-sid" else output

    monkeypatch.setattr(dcsync, "run_check", run)
    trustees = dcsync.dcsync_check("dc", "example.test", "user", "password", set(), [])
    assert trustees == [
        {"name": "operator", "sid": user_sid, "rights": ["GenericAll"], "complete": True}
    ]
    assert calls[1][1][calls[1][1].index("-action") + 1] == "read"
    assert calls[1][1][calls[1][1].index("-target-sid") + 1] == DOMAIN_SID


def test_dcsync_rejects_malformed_scoped_full_control():
    output = _full_control_ace(
        0, "scoped", f"{DOMAIN_SID}-2000", "0xf01ff",
        ace_type="ACCESS_ALLOWED_OBJECT_ACE",
        object_type="[*]     Flags : ACE_OBJECT_TYPE_PRESENT\n",
    )
    with pytest.raises(RuntimeError, match="object type"):
        dcsync._parse_dcsync_aces(output)


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


def test_generic_all_is_not_suppressed_by_expected_dcsync_exclusions(monkeypatch):
    output = io.StringIO()
    findings = []
    session = {
        "dc_ip": "dc", "domain": "example.test", "standard_user": "user",
        "expected_dcsync_sids": [f"{DOMAIN_SID}-2001", f"{DOMAIN_SID}-2002"],
    }
    trustees = [
        {"name": "expected", "sid": f"{DOMAIN_SID}-2001",
         "rights": ["GenericAll"], "complete": True},
        {"name": "MSOL_connector", "sid": f"{DOMAIN_SID}-2003",
         "rights": ["GenericAll"], "complete": True},
        {"name": "expected_replication", "sid": f"{DOMAIN_SID}-2002",
         "rights": ["DS-Replication-Get-Changes"], "complete": True},
        {"name": "MSOL_other", "sid": f"{DOMAIN_SID}-2004",
         "rights": ["DS-Replication-Get-Changes"], "complete": True},
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
    privileged.run_privileged_group_checks("pw")
    assert f"{DOMAIN_SID}-2001" in output.getvalue()
    assert f"{DOMAIN_SID}-2003" in output.getvalue()
    assert f"{DOMAIN_SID}-2002" not in output.getvalue()
    assert f"{DOMAIN_SID}-2004" not in output.getvalue()
    finding = next(finding for finding in findings if finding.id == "PRIV-005")
    assert len(finding.evidence) == 2
    assert all("GenericAll" in entry for entry in finding.evidence)


@pytest.mark.parametrize(("count", "phrase"), [
    (1, "1 non-default principal was granted permissions"),
    (2, "2 non-default principals were granted permissions"),
])
def test_dcsync_finding_only_reports_complete_rights(count, phrase):
    complete = [
        {"name": f"user-{i}", "sid": f"{DOMAIN_SID}-{i}", "rights": ["right"], "complete": True}
        for i in range(count)
    ]
    partial = {"name": "partial", "sid": f"{DOMAIN_SID}-999", "rights": [], "complete": False}
    assert dcsync.dcsync_findings([partial]) == []
    finding = dcsync.dcsync_findings([*complete, partial])[0]
    assert phrase in finding.commentary
    assert "Filtered Set is an additional right" not in finding.commentary
    assert "Some reported principals" not in finding.commentary
    assert len(finding.evidence) == count
    assert all("partial" not in entry for entry in finding.evidence)
    evidence = format_finding_sections(finding)["Evidence"]
    noun = "principal was" if count == 1 else "principals were"
    assert f"The following {noun} found to have the complete core DCSync right set" in evidence
    assert "DS-Replication-Get-Changes, DS-Replication-Get-Changes-All" in evidence
    assert f"1. `user-0` ({DOMAIN_SID}-0)" in evidence
    if count == 2:
        assert f"2. `user-1` ({DOMAIN_SID}-1)" in evidence
    assert f"The following {noun} found" in render_html([finding])


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
