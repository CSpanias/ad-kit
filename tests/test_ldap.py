import pytest

from ad_kit.checks import ldap


@pytest.mark.parametrize(
    ("output", "expected_status", "expected_finding"),
    [
        (
            "LDAP 192.168.239.130 389 MOLLYSEC-DC01 [-] Error in "
            "searchRequest -> operationsError: successful bind must be "
            "completed on the connection.\n"
            "LDAP 192.168.239.130 389 MOLLYSEC-DC01 [+] "
            "molly.sec\\:********\n",
            "[red]✗ Permitted[/red]",
            "LDAP-003",
        ),
        (
            "LDAP 192.168.239.130 389 MOLLYSEC-DC01 [-] Error in "
            "searchRequest -> operationsError: successful bind must be "
            "completed on the connection.\n",
            "[yellow]⚠ Unknown[/yellow]",
            None,
        ),
        (
            "LDAP 192.168.239.130 389 MOLLYSEC-DC01 [+] "
            "molly.sec\\:********\n",
            "[red]✗ Permitted[/red]",
            "LDAP-003",
        ),
    ],
)
def test_ldap_check_reports_null_bind_result(
    monkeypatch,
    output,
    expected_status,
    expected_finding,
):
    dc_hostname = "MOLLYSEC-DC01.MOLLY.SEC"
    loaded_findings = []
    commands = []

    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: [dc_hostname])
    monkeypatch.setattr(ldap, "record_incomplete", lambda *_args: None)

    def fake_run_check(name, command):
        commands.append(command)
        if name == f"ldap-anonymous-users-{dc_hostname}":
            return "LDAP dc 389 DC Enumerated 1 domain users: EXAMPLE"
        assert name == f"ldap-{dc_hostname}"
        assert command == [
            "nxc", "ldap", dc_hostname, "-u", "", "-p", "",
        ]
        return output

    def fake_load_finding(category, finding_id):
        assert category == "ldap"
        loaded_findings.append(finding_id)
        return ldap.Finding(
            id=finding_id,
            title=finding_id,
            commentary="",
            remediation="",
        )

    monkeypatch.setattr(ldap, "run_check", fake_run_check)
    monkeypatch.setattr(ldap, "load_finding", fake_load_finding)

    results, findings = ldap.ldap_check()

    assert results[0]["anonymous_bind"] == expected_status
    assert [finding.id for finding in findings] == (
        [expected_finding] if expected_finding else []
    )
    assert loaded_findings == ([expected_finding] if expected_finding else [])
    assert len(commands) == (2 if expected_finding else 1)
    if expected_finding:
        assert commands[1][-1] == "--users"
    if findings:
        assert findings[0].affected_assets == [dc_hostname]


def test_ldap_user_search_without_results_is_not_treated_as_denied(monkeypatch):
    incomplete = []
    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: ["DC"])
    monkeypatch.setattr(
        ldap, "run_check",
        lambda name, _command: (
            "LDAP dc 389 DC [+] example\\:********"
            if name == "ldap-DC"
            else "LDAP dc 389 DC [-] searchRequest operationsError"
        ),
    )
    monkeypatch.setattr(ldap, "record_incomplete", lambda *args: incomplete.append(args))
    monkeypatch.setattr(
        ldap, "load_finding", lambda *_args: ldap.Finding("LDAP-003", "", "", "")
    )
    results, findings = ldap.ldap_check()
    assert results[0]["anonymous_bind"] == "[red]✗ Permitted[/red]"
    assert findings[0].id == "LDAP-003"
    assert any("No confirmed user enumeration" in entry[2] for entry in incomplete)
