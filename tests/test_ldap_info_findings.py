import io
import xml.etree.ElementTree as ET
from contextlib import nullcontext

import pytest
from rich.console import Console

from ad_kit.checks import ldap_info
from ad_kit.commands.checks import privileged
from ad_kit.reporting import json as json_report
from ad_kit.reporting import sureformat


@pytest.mark.parametrize("label", ["Info", "info"])
def test_info_module_output_separates_username_and_preserves_value(monkeypatch, label):
    monkeypatch.setattr(ldap_info, "track_items", lambda items, _label: items)
    monkeypatch.setattr(
        ldap_info,
        "run_check",
        lambda name, *_args, **_kwargs: (
            f"GET-INFO-USERS dc 389 DC User: freya    {label}: Lab credential token: FAKE-TOKEN"
            if name == "ldap-info-users" else ""
        ),
    )

    result = ldap_info.ldap_info_check("dc", "user", "password")

    assert result["info_fields"] == [
        {"user": "freya", "value": "Lab credential token: FAKE-TOKEN"}
    ]


def test_ldap_info_table_shows_masked_previews(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(privileged, "console", Console(file=output, width=160))
    monkeypatch.setattr(privileged, "print_section", lambda *_args: None)
    monkeypatch.setattr(privileged, "require_session", lambda: {
        "dc_ip": "dc", "standard_user": "user",
    })
    monkeypatch.setattr(privileged, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(privileged, "record_findings", lambda *_args: None)
    monkeypatch.setattr(privileged, "ldap_info_check", lambda *_args: {
        "descriptions": [{"user": "freya", "value": "password=secret"}],
        "info_fields": [{"user": "freya", "value": "token=abc"}],
        "user_passwords": ["User: freya userPassword: TestSecret"],
        "unix_passwords": ["User: freya unixUserPassword: abc"],
    })

    privileged.run_ldap_info_checks("password")

    text = output.getvalue()
    assert "Value preview" in text
    assert "pass[REDACTED]" in text
    assert "toke[REDACTED]" in text
    assert "Test[REDACTED]" in text
    assert "password=secret" not in text
    assert "token=abc" not in text
    assert "TestSecret" not in text
    assert "abc" not in text


@pytest.mark.parametrize(
    ("attributes", "expected_evidence"),
    [
        ({"description"}, 1),
        ({"info"}, 1),
        ({"userPassword"}, 1),
        ({"unixUserPassword"}, 1),
        ({"description", "info", "userPassword", "unixUserPassword"}, 4),
        (set(), 0),
    ],
)
def test_ldap_info_finding_covers_only_observed_attributes(
    monkeypatch, tmp_path, attributes, expected_evidence
):
    results = {
        "descriptions": [{"user": "alice", "value": "password note"}]
        if "description" in attributes else [{"user": "bob", "value": "ordinary note"}],
        "info_fields": [{"user": "alice", "value": "credential note"}]
        if "info" in attributes else [],
        "user_passwords": ["User: alice userPassword: example"]
        if "userPassword" in attributes else [],
        "unix_passwords": ["User: bob unixUserPassword: example"]
        if "unixUserPassword" in attributes else [],
    }
    findings = []
    monkeypatch.setattr(privileged, "require_session", lambda: {
        "dc_ip": "192.0.2.1", "standard_user": "user",
    })
    monkeypatch.setattr(privileged, "progress", lambda *_args: nullcontext())
    monkeypatch.setattr(privileged, "ldap_info_check", lambda *_args: results)
    monkeypatch.setattr(privileged, "record_findings", findings.extend)
    monkeypatch.setattr(privileged, "print_section", lambda *_args: None)
    monkeypatch.setattr(privileged.console, "print", lambda *_args: None)

    privileged.run_ldap_info_checks("password")

    if not attributes:
        assert findings == []
        return
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "LDAPINFO-001"
    assert len(finding.evidence) == expected_evidence
    if "description" in attributes:
        assert (
            "Account `alice` contained potentially sensitive information "
            "within the LDAP `description` attribute: `password note`."
        ) in finding.evidence
    if "info" in attributes:
        assert (
            "Account `alice` contained potentially sensitive information "
            "within the LDAP `info` attribute: `credential note`."
        ) in finding.evidence
    assert all(
        entry in finding.evidence
        for entry in results["user_passwords"] + results["unix_passwords"]
    )
    for attribute in ("description", "info", "userPassword", "unixUserPassword"):
        assert (f"`{attribute}`" in finding.commentary) == (attribute in attributes)
        assert (f"`{attribute}`" in finding.remediation) == (attribute in attributes)
    if attributes & {"userPassword", "unixUserPassword"}:
        assert "does not establish that they are usable credentials" in finding.commentary
    assert len(finding.references) == len(set(finding.references))

    json_report.reset()
    json_report.collect(findings)
    integration = json_report.get_findings()
    assert [item["id"] for item in integration] == ["LDAPINFO-001"]
    path = tmp_path / "findings.xml"
    sureformat.write_findings(path, "example.test", integration)
    entries = ET.parse(path).findall(".//vulnerability")
    assert [entry.attrib["id"] for entry in entries] == ["SC-9182"]
    assert entries[0].findtext("information") == integration[0]["description"]
    json_report.reset()
