import pytest

from ad_kit.checks import password_never_expires
from ad_kit.core.exceptions import CheckExecutionError


def test_password_never_expires_parses_netexec_table(monkeypatch):
    prefix = "LDAP 192.168.77.10 389 DC01 "
    output = "\n".join([
        prefix + "[+] adkit.test\\sylune:********",
        prefix + f"{'-Username-':<30}{'-Last PW Set-':<20}",
        prefix + f"{'Administrator':<30}{'2026-11-27 20:54:44':<20}",
        prefix + f"{'poppy':<30}{'2026-11-27 21:45:08':<20}",
        prefix + f"{'freya':<30}{'<never>':<20}",
        prefix + f"{'Service Account':<30}{'':<20}",
        prefix + f"{'COMPUTER$':<30}{'2026-11-27 21:45:08':<20}",
    ])
    monkeypatch.setattr(password_never_expires, "run_check", lambda *_args: output)
    results, findings = password_never_expires.password_never_expires_check("dc", "user", "pw")
    assert results["accounts"] == ["Administrator", "Service Account", "freya", "poppy"]
    assert [finding.id for finding in findings] == ["PASS-003"]


def test_password_never_expires_accepts_explicit_no_entries(monkeypatch):
    output = "LDAP dc 389 DC [+] example\\user:********\nLDAP dc 389 DC [-] No entries found!"
    monkeypatch.setattr(password_never_expires, "run_check", lambda *_args: output)
    results, findings = password_never_expires.password_never_expires_check("dc", "user", "pw")
    assert results["account_count"] == 0
    assert not findings


@pytest.mark.parametrize("output", [
    "LDAP dc 389 DC [+] example\\user:********",
    "LDAP dc 389 DC [+] example\\user:********\n"
    "LDAP dc 389 DC [-] searchRequest operationsError\nLDAP dc 389 DC [-] No entries found!",
    "LDAP dc 389 DC [+] example\\user:********\n"
    "LDAP dc 389 DC -Username-                    -Last PW Set-\n"
    "LDAP dc 389 DC user                          invalid date",
])
def test_password_never_expires_rejects_incomplete_output(monkeypatch, output):
    monkeypatch.setattr(password_never_expires, "run_check", lambda *_args: output)
    with pytest.raises(CheckExecutionError):
        password_never_expires.password_never_expires_check("dc", "user", "pw")


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
    assert findings[0].evidence[0].startswith("A total of two enabled user accounts have passwords")
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
    assert findings[0].evidence[0].startswith(
        "A total of one enabled user account has a password configured to never expire"
    )