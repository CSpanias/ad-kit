from ad_kit.checks import password_never_expires


def test_password_never_expires_check_returns_enabled_user_accounts_and_finding(monkeypatch):
    output = """LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: GAVIN_HEAD Status: enabled
LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: MAY_HARVEY Status: enabled
LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: Guest Status: disabled
"""
    loaded_findings = []

    def fake_run_check(name, command):
        assert name == "password-never-expires"
        assert command == [
            "nxc",
            "ldap",
            "192.168.239.130",
            "-u",
            "poppy",
            "-p",
            "password",
            "--password-never-expires",
        ]
        return output

    def fake_load_finding(category, finding_id):
        assert category == "password_policy"
        assert finding_id == "PASS-003"
        loaded_findings.append(finding_id)
        return password_never_expires.Finding(
            id=finding_id,
            title=finding_id,
            commentary="",
            remediation="",
        )

    monkeypatch.setattr(password_never_expires, "run_check", fake_run_check)
    monkeypatch.setattr(password_never_expires, "load_finding", fake_load_finding)

    results, findings = password_never_expires.password_never_expires_check(
        "192.168.239.130",
        "poppy",
        "password",
    )

    assert results == {
        "accounts": ["GAVIN_HEAD", "MAY_HARVEY"],
        "account_count": 2,
    }
    assert [finding.id for finding in findings] == ["PASS-003"]
    assert findings[0].evidence[0].startswith("A total of 2 enabled user account(s)")
    assert loaded_findings == ["PASS-003"]


def test_password_never_expires_check_ignores_disabled_accounts(monkeypatch):
    output = """LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: Guest Status: disabled
"""

    monkeypatch.setattr(password_never_expires, "run_check", lambda *_args: output)

    def unexpected_finding(*_args):
        raise AssertionError("disabled accounts must not create a finding")

    monkeypatch.setattr(password_never_expires, "load_finding", unexpected_finding)

    results, findings = password_never_expires.password_never_expires_check(
        "192.168.239.130",
        "poppy",
        "password",
    )

    assert results == {"accounts": [], "account_count": 0}
    assert findings == []


def test_password_never_expires_check_ignores_machine_accounts(monkeypatch):
    output = """LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: KERBEROS.MICROSOFTONLINE.COM$ Status: enabled
LDAP 192.168.239.130 389 MOLLYSEC-DC01 User: GAVIN_HEAD Status: enabled
"""

    monkeypatch.setattr(password_never_expires, "run_check", lambda *_args: output)

    def fake_load_finding(category, finding_id):
        return password_never_expires.Finding(
            id=finding_id,
            title=finding_id,
            commentary="",
            remediation="",
        )

    monkeypatch.setattr(password_never_expires, "load_finding", fake_load_finding)

    results, findings = password_never_expires.password_never_expires_check(
        "192.168.239.130",
        "poppy",
        "password",
    )

    assert results == {
        "accounts": ["GAVIN_HEAD"],
        "account_count": 1,
    }
    assert [finding.id for finding in findings] == ["PASS-003"]