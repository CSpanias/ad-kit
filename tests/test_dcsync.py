from ad_kit.checks import dcsync

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

    trustees, findings = dcsync.dcsync_check(
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
    assert [finding.id for finding in findings] == ["PRIV-005"]
    assert "MARA_DANIEL" in findings[0].evidence[0]
    assert commands[0][1][-1] == "--get-sid"
    assert commands[1][1][commands[1][1].index("-target-sid") + 1] == DOMAIN_SID
    assert commands[1][1][-1] == "example.test/poppy:Password123!"
    assert commands[1][2] == [
        "Password123!",
        "example.test/poppy:Password123!",
    ]
