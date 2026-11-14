from ad_kit.checks import passwd_notreqd


def test_passwd_notreqd_check_returns_enabled_accounts_and_finding(monkeypatch):
    output = """LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: GAVIN_HEAD Status: enabled
LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: JEREMIAH_HARDIN Status: enabled
LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: MAY_HARVEY Status: enabled
LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: Guest Status: disabled
"""
    loaded_findings = []

    def fake_run_check(name, command):
        assert name == "passwd-notreqd"
        assert command == [
            "nxc",
            "ldap",
            "192.168.239.130",
            "-u",
            "poppy",
            "-p",
            "password",
            "--password-not-required",
        ]
        return output

    def fake_load_finding(category, finding_id):
        assert category == "password_policy"
        assert finding_id == "PASS-002"
        loaded_findings.append(finding_id)
        return passwd_notreqd.Finding(
            id=finding_id,
            title=finding_id,
            commentary="",
            remediation="",
        )

    monkeypatch.setattr(passwd_notreqd, "run_check", fake_run_check)
    monkeypatch.setattr(passwd_notreqd, "load_finding", fake_load_finding)

    results, findings = passwd_notreqd.passwd_notreqd_check(
        "192.168.239.130",
        "poppy",
        "password",
    )

    assert results == {
        "accounts": ["GAVIN_HEAD", "JEREMIAH_HARDIN", "MAY_HARVEY"],
        "account_count": 3,
    }
    assert [finding.id for finding in findings] == ["PASS-002"]
    assert findings[0].evidence[0].startswith("3 enabled account(s)")
    assert loaded_findings == ["PASS-002"]


def test_passwd_notreqd_check_ignores_disabled_accounts(monkeypatch):
    monkeypatch.setattr(
        passwd_notreqd,
        "run_check",
        lambda *_args: "LDAP 192.168.239.130 389 MOLLYSEC-DC01 "
        "User: Guest Status: disabled\n",
    )

    def unexpected_finding(*_args):
        raise AssertionError("disabled accounts must not create a finding")

    monkeypatch.setattr(
        passwd_notreqd,
        "load_finding",
        unexpected_finding,
    )

    results, findings = passwd_notreqd.passwd_notreqd_check(
        "192.168.239.130",
        "poppy",
        "password",
    )

    assert results == {"accounts": [], "account_count": 0}
    assert findings == []
