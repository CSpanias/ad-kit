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
            "[green]✓ Disabled[/green]",
            None,
        ),
        (
            "LDAP 192.168.239.130 389 MOLLYSEC-DC01 [-] Error in "
            "searchRequest -> operationsError: successful bind must be "
            "completed on the connection.\n",
            "[green]✓ Disabled[/green]",
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

    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: [dc_hostname])

    def fake_run_check(name, command):
        assert name == "ldap-MOLLYSEC-DC01"
        assert command == [
            "nxc", "ldap", "MOLLYSEC-DC01", "-u", "", "-p", "",
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
    if findings:
        assert findings[0].affected_assets == [dc_hostname]
