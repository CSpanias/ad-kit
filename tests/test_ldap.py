import threading

import pytest

from ad_kit.checks import ldap
from ad_kit.core import util
from ad_kit.core.checks import CheckEvidence, append_captured_evidence, capture_check_evidence
from ad_kit.core.exceptions import CheckExecutionError
from ad_kit.core.findings import load_finding
from ad_kit.reporting.html import render_html
from ad_kit.reporting.markdown import format_finding_sections, format_paragraphs


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
    commands = []

    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: [dc_hostname])
    monkeypatch.setattr(ldap, "record_incomplete", lambda *_args: None)

    def fake_run_check(name, command, **_kwargs):
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
        lambda name, _command, **_kwargs: (
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
    assert results[0]["anonymous_bind"] == "[green]✓ Disabled[/green]"
    assert not findings
    assert any("No confirmed user enumeration" in entry[2] for entry in incomplete)


@pytest.mark.parametrize(("outputs", "expected"), [
    (
        [2],
        "Anonymous user account enumeration was confirmed on the affected domain controller.",
    ),
    (
        [2] * 7,
        "Anonymous user account enumeration was confirmed on all affected domain controllers.",
    ),
    (
        [5, 0, None],
        "Anonymous user account enumeration was confirmed on the affected domain controller.",
    ),
    (
        [3] * 10 + [None],
        "Anonymous user account enumeration was confirmed on all affected domain controllers.",
    ),
])
def test_ldap_anonymous_finding_reports_user_enumeration(monkeypatch, outputs, expected):
    hosts = [f"DC{i}" for i in range(len(outputs))]
    output_by_host = dict(zip(hosts, outputs, strict=True))
    incomplete = []
    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: hosts)
    monkeypatch.setattr(ldap, "record_incomplete", lambda *args: incomplete.append(args))

    def fake_run(name, command, **_kwargs):
        if name.startswith("ldap-anonymous-users-"):
            host = name.removeprefix("ldap-anonymous-users-")
            count = output_by_host[host]
            if count is None:
                raise CheckExecutionError(name, command, returncode=1)
            if count == "inconclusive":
                return "LDAP dc 389 DC [-] searchRequest operationsError"
            return f"LDAP dc 389 DC Enumerated {count} domain users: EXAMPLE"
        return "LDAP dc 389 DC [+] example\\:********"

    monkeypatch.setattr(ldap, "run_check", fake_run)
    results, findings = ldap.ldap_check()
    finding = next(finding for finding in findings if finding.id == "LDAP-003")

    for result in results:
        output = output_by_host[result["dc_hostname"]]
        assert result["anonymous_users"] == (output if isinstance(output, int) else None)
        if isinstance(output, int) and output > 0:
            assert result["anonymous_bind"] == "[red]✗ Permitted[/red]"
        elif isinstance(output, int):
            assert result["anonymous_bind"] == "[green]✓ Disabled[/green]"
        else:
            assert result["anonymous_bind"] == "[green]✓ Disabled[/green]"
    assert format_paragraphs(finding.commentary).endswith(expected)
    assert expected in render_html([finding])
    assert "shares" not in expected
    incomplete_enumerations = [
        entry for entry in incomplete if entry[0] == "LDAP anonymous user enumeration"
    ]
    assert len(incomplete_enumerations) == (
        outputs.count(None) + outputs.count("inconclusive")
    )


def test_ldap_anonymous_summary_excludes_controllers_without_confirmed_bind(monkeypatch):
    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: ["DC1", "DC2"])
    monkeypatch.setattr(ldap, "record_incomplete", lambda *_args: None)
    monkeypatch.setattr(
        ldap, "run_check",
        lambda name, *_args, **_kwargs: (
            "LDAP dc 389 DC Enumerated 3 domain users: EXAMPLE"
            if name == "ldap-anonymous-users-DC1"
            else "LDAP dc 389 DC [+] example\\:********"
            if name == "ldap-DC1"
            else "LDAP dc 389 DC [-] STATUS_LOGON_FAILURE"
        ),
    )
    _, findings = ldap.ldap_check()
    finding = next(finding for finding in findings if finding.id == "LDAP-003")

    assert finding.affected_assets == ["DC1"]
    assert "enumeration was confirmed on the affected domain controller" in finding.commentary


@pytest.mark.parametrize(("count", "noun", "count_word"), [
    (1, "Domain Controller (DC)", "one"),
    (2, "Domain Controllers (DCs)", "two"),
    (10, "Domain Controllers (DCs)", "10"),
])
def test_ldap_commentary_counts_affected_controllers(monkeypatch, count, noun, count_word):
    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: [f"DC{i}" for i in range(count)])
    monkeypatch.setattr(ldap, "record_incomplete", lambda *_args: None)
    monkeypatch.setattr(ldap, "load_finding", load_finding)
    monkeypatch.setattr(
        ldap, "run_check",
        lambda *_args, **_kwargs: (
            "LDAP dc 389 DC (signing:None) (channel binding:Never)\n"
            "LDAP dc 389 DC [+] example\\:********\n"
            "LDAP dc 389 DC Enumerated 1 domain users: EXAMPLE"
        ),
    )
    _, findings = ldap.ldap_check()
    by_id = {finding.id: finding for finding in findings}
    assert f"{count_word} {noun} did not require LDAP signing" in by_id["LDAP-001"].commentary
    assert f"{count_word}\n{noun}." in by_id["LDAP-002"].commentary
    assert f"{count_word} {noun} permitted anonymous LDAP binds" in by_id["LDAP-003"].commentary
    for finding in findings:
        assert "Lightweight Directory Access Protocol (LDAP)" in finding.commentary
        assert "Lightweight Directory Access Protocol (LDAP)" in finding.remediation
        remediation = format_finding_sections(finding)["Remediation"]
        assert "\n- " in remediation and "### References" in remediation
        assert len(finding.affected_assets) == count
    assert "does not establish that all LDAP traffic is unsigned" in format_paragraphs(
        by_id["LDAP-001"].commentary
    )
    assert "does not establish that directory searches or user enumeration are permitted" in (
        format_paragraphs(by_id["LDAP-003"].commentary)
    )
    assert "`When Supported` only as an interim measure" in by_id["LDAP-002"].remediation


def test_missing_tls_certificate_does_not_confirm_channel_binding_is_disabled(monkeypatch):
    incomplete = []
    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: ["DC"])
    monkeypatch.setattr(ldap, "record_incomplete", lambda *args: incomplete.append(args))
    monkeypatch.setattr(
        ldap, "run_check",
        lambda *_args, **_kwargs: (
            "LDAP dc 389 DC (signing:Enforced) (channel binding:No TLS cert)\n"
            "LDAP dc 389 DC [-] STATUS_LOGON_FAILURE"
        ),
    )

    results, findings = ldap.ldap_check()

    assert results[0]["channel_binding"] == "[yellow]⚠ Unknown[/yellow]"
    assert not any(finding.id == "LDAP-002" for finding in findings)
    assert any("channel binding could not be verified" in reason for _, _, reason in incomplete)


def test_ldap_parallel_controllers_keep_per_host_evidence_and_order(monkeypatch):
    barrier = threading.Barrier(2)
    calls = []
    lock = threading.Lock()
    monkeypatch.setattr(ldap, "load_dc_hostnames", lambda: ["DC1", "DC2", "dc1."])
    monkeypatch.setattr(ldap, "record_incomplete", lambda *_args: None)
    monkeypatch.setattr(
        ldap, "load_finding", lambda _category, name: ldap.Finding(name, name, "", "")
    )

    def run(name, command, **_kwargs):
        with lock:
            calls.append(name)
        if name.startswith("ldap-anonymous-users-"):
            output = "LDAP dc 389 DC Enumerated 1 domain users: EXAMPLE"
        else:
            barrier.wait(timeout=5)
            output = (
                "LDAP (signing:None) (channel binding:Always)\n"
                "LDAP dc 389 DC [+] example\\:********"
            )
        append_captured_evidence([CheckEvidence(name, command, output, "")])
        return output

    monkeypatch.setattr(ldap, "run_check", run)
    with util.check_workers(2), capture_check_evidence() as evidence:
        results, findings = ldap.ldap_check()

    assert [item["dc_hostname"] for item in results] == ["DC1", "DC2"]
    assert [finding.id for finding in findings] == ["LDAP-001", "LDAP-003"]
    assert [record.name for record in evidence] == [
        "ldap-DC1", "ldap-anonymous-users-DC1", "ldap-DC2", "ldap-anonymous-users-DC2",
    ]
    for dc in ("DC1", "DC2"):
        assert calls.index(f"ldap-{dc}") < calls.index(f"ldap-anonymous-users-{dc}")
