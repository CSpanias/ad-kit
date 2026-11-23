import json
import xml.etree.ElementTree as ET

import pytest
from typer.testing import CliRunner

from ad_kit.cli import app
from ad_kit.commands import check
from ad_kit.core import util
from ad_kit.core.finding import Finding
from ad_kit.reporting import results, sureformat


def _vulnerabilities(path):
    root = ET.parse(path).getroot()
    item = root.find("item")
    service = item.find("./services/service")
    return root, item, service, service.findall("./vulnerabilities/vulnerability")


@pytest.mark.parametrize("dc", [None, "DC01.example.com"])
def test_sureformat_export_matches_adapter_and_optional_dc_split(monkeypatch, tmp_path, dc):
    findings = [
        Finding("SMB-001", "SMB", "SMB signing details.", ""),
        Finding("LDAP-001", "LDAP", "LDAP signing details.", ""),
        Finding("NOPAC-001", "NoPAC", "NoPAC details.", ""),
        Finding("OTHER-001", "Unmapped", "Other details.", ""),
        Finding("PRIV-001", "Privileged accounts", "Privilege details.", ""),
    ]
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(check, "require_session", lambda: {"domain": "EXAMPLE.COM"})
    monkeypatch.setitem(
        check.AVAILABLE_CHECKS,
        "fake",
        check.CheckDefinition(lambda password: results.record_findings(findings), False),
    )

    check.run_selected_checks(["fake"], csacyber=True, dc=dc)

    root, item, service, vulnerabilities = _vulnerabilities(tmp_path / "ad-kit_findings.xml")
    assert root.attrib == {"source": "SureFormat", "version": "1.0.0"}
    assert item.attrib == {"ipaddress": "", "hostname": "example.com"}
    assert service.attrib == {"name": "", "port": "", "protocol": "tcp"}
    assert [v.attrib["id"] for v in vulnerabilities] == (
        ["SC-10674", "SC-7704"]
        if dc else ["SC-6080", "SC-3704", "SC-10674", "SC-7704"]
    )
    smb = next(v for v in vulnerabilities if v.attrib["id"] == "SC-7704")
    assert smb.findtext("information") == "SMB signing details."
    assert (tmp_path / "ad-kit_findings.html").exists()
    assert not (tmp_path / "ad-kit_findings.json").exists()
    dc_path = tmp_path / "ad-kit_findings-dc.xml"
    if dc:
        _, dc_item, _, dc_vulnerabilities = _vulnerabilities(dc_path)
        assert dc_item.attrib["hostname"] == dc
        assert [v.attrib["id"] for v in dc_vulnerabilities] == ["SC-6080", "SC-3704"]
    else:
        assert not dc_path.exists()


def test_sureformat_escapes_data_and_warns_for_missing_mapping(monkeypatch, tmp_path):
    warnings = []
    monkeypatch.setattr(sureformat, "print_warning", warnings.append)
    path = tmp_path / "test.xml"
    sureformat.write_findings(path, "example&domain", [
        {"id": "SMB-001", "description": "A < B & C"},
        {"id": "unmapped", "description": "omitted"},
    ])
    _, item, _, vulnerabilities = _vulnerabilities(path)
    assert item.attrib["hostname"] == "example&domain"
    assert [v.findtext("information") for v in vulnerabilities] == ["A < B & C"]
    assert warnings == ["No SureFormat mapping found for finding: unmapped"]


def test_sureformat_combines_findings_with_the_same_platform_id(tmp_path):
    path = tmp_path / "test.xml"
    sureformat.write_findings(path, "example.test", [
        {"id": "ASREP-001", "description": "Roastable accounts."},
        {"id": "ASREP-002", "description": "Privileged accounts."},
        {"id": "PRIV-001", "description": "Privileged membership."},
    ])
    _, _, _, vulnerabilities = _vulnerabilities(path)
    assert [v.attrib["id"] for v in vulnerabilities] == ["SC-3550", "SC-10674"]
    assert vulnerabilities[0].findtext("information") == (
        "Roastable accounts.\nPrivileged accounts."
    )
    assert vulnerabilities[1].findtext("information") == "Privileged membership."


def test_full_run_exports_xml_without_replacing_previous_json(monkeypatch, tmp_path):
    previous_json = tmp_path / "ad-kit_findings.json"
    previous_json.write_text("previous output", encoding="utf-8")
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(check, "require_session", lambda: {"domain": "example.com"})
    monkeypatch.setattr(
        check, "run_ldap_checks",
        lambda: results.record_findings([Finding("LDAP-002", "LDAP", "", "")]),
    )
    monkeypatch.setattr(check, "run_smb_checks", lambda *_: "password")
    monkeypatch.setattr(check, "_run_authed", lambda _name, _check, password: password)

    check.run_checks(csacyber=True)

    _, _, _, vulnerabilities = _vulnerabilities(tmp_path / "ad-kit_findings.xml")
    assert [v.attrib["id"] for v in vulnerabilities] == ["SC-6643"]
    assert previous_json.read_text(encoding="utf-8") == "previous output"


def test_cli_creates_domain_and_dc_xml_from_session(monkeypatch, tmp_path):
    (tmp_path / "session.json").write_text(json.dumps({"domain": "example.com"}), encoding="utf-8")
    monkeypatch.setattr(util, "ARTEFACTS_DIR", tmp_path)
    monkeypatch.setitem(
        check.AVAILABLE_CHECKS,
        "ldap",
        check.CheckDefinition(
            lambda password: results.record_findings([Finding("LDAP-003", "LDAP", "", "")]),
            False,
        ),
    )

    result = CliRunner().invoke(app, ["check", "ldap", "--csacyber", "--dc", "dc.example.com"])

    assert result.exit_code == 0, result.output
    _, domain_item, _, domain_vulnerabilities = _vulnerabilities(tmp_path / "ad-kit_findings.xml")
    _, dc_item, _, dc_vulnerabilities = _vulnerabilities(tmp_path / "ad-kit_findings-dc.xml")
    assert domain_item.attrib["hostname"] == "example.com"
    assert not domain_vulnerabilities
    assert dc_item.attrib["hostname"] == "dc.example.com"
    assert [v.attrib["id"] for v in dc_vulnerabilities] == ["SC-1000"]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["check", "--csacyber"], None),
        (["check", "all", "--csacyber"], None),
        (["check", "--csacyber", "ldap", "--dc", "dc.example.com"], ["ldap"]),
        (["check", "run", "ldap", "smb", "--csacyber"], ["ldap", "smb"]),
        (["check", "--csacyber", "--dc", "dc.example.com", "run", "ldap"], ["ldap"]),
    ],
)
def test_cli_dispatches_sureformat_options(monkeypatch, args, expected):
    calls = []
    monkeypatch.setattr(check, "require_session", lambda: {"domain": "example.com"})
    monkeypatch.setattr(
        check, "run_checks", lambda **kwargs: calls.append((None, kwargs))
    )
    monkeypatch.setattr(
        check, "run_selected_checks", lambda modules, **kwargs: calls.append((modules, kwargs))
    )

    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    expected_dc = "dc.example.com" if "--dc" in args else None
    assert calls == [(expected, {"csacyber": True, "dc": expected_dc})]


@pytest.mark.parametrize(
    ("args", "expected_workers"),
    [
        (["check"], 4),
        (["check", "--workers", "2"], 2),
        (["check", "all", "--workers", "16"], 16),
        (["check", "--workers", "3", "ldap"], 3),
        (["check", "smb", "--workers", "1"], 1),
        (["check", "run", "ldap", "smb", "--workers", "2"], 2),
    ],
)
def test_cli_applies_worker_limit_to_each_check_entrypoint(monkeypatch, args, expected_workers):
    seen = []
    monkeypatch.setattr(
        check, "run_checks", lambda **_kwargs: seen.append(util._check_workers.get())
    )
    monkeypatch.setattr(
        check, "run_selected_checks",
        lambda _modules, **_kwargs: seen.append(util._check_workers.get()),
    )
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert seen == [expected_workers]
    assert util._check_workers.get() == 4


@pytest.mark.parametrize("args", [
    ["check", "--workers", "0"],
    ["check", "ldap", "--workers", "17"],
    ["check", "--workers", "2", "smb", "--workers", "3"],
])
def test_cli_rejects_invalid_or_duplicate_worker_limits(monkeypatch, args):
    monkeypatch.setattr(check, "run_checks", lambda **_kwargs: pytest.fail("checks ran"))
    monkeypatch.setattr(
        check, "run_selected_checks", lambda *_args, **_kwargs: pytest.fail("checks ran")
    )
    result = CliRunner().invoke(app, args)
    assert result.exit_code != 0
    assert "--workers" in result.output


@pytest.mark.parametrize(
    ("args", "expected_modules", "expected_exclusions"),
    [
        (["check", "--exclude", "ldap"], None, {"ldap"}),
        (["check", "all", "--exclude", "ldap,smb"], None, {"ldap", "smb"}),
        (["check", "--exclude", "ldap, smb", "all"], None, {"ldap", "smb"}),
        (["check", "run", "ldap", "smb", "--exclude", "ldap"], ["smb"], set()),
        (["check", "--exclude", "dns", "smb"], ["smb"], set()),
    ],
)
def test_cli_excludes_checks(monkeypatch, args, expected_modules, expected_exclusions):
    calls = []
    monkeypatch.setattr(
        check, "run_checks", lambda **kwargs: calls.append((None, kwargs.get("exclude", set())))
    )
    monkeypatch.setattr(
        check, "run_selected_checks", lambda modules, **_kwargs: calls.append((modules, set()))
    )
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert calls == [(expected_modules, expected_exclusions)]


@pytest.mark.parametrize("args", [
    [
        "check", "--workers", "8", "--exclude", "ldap,smb",
        "all", "--csacyber", "--dc", "example.com DCs",
    ],
    [
        "check", "all", "--csacyber", "--dc", "example.com DCs",
        "--workers", "8", "--exclude", "ldap,smb",
    ],
])
def test_cli_exclusions_combine_with_export_and_worker_options(monkeypatch, args):
    calls = []
    monkeypatch.setattr(check, "require_session", lambda: {"domain": "example.com"})
    monkeypatch.setattr(
        check, "run_checks",
        lambda **kwargs: calls.append((util._check_workers.get(), kwargs)),
    )
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert calls == [(8, {
        "csacyber": True, "dc": "example.com DCs", "exclude": {"ldap", "smb"},
    })]


@pytest.mark.parametrize("args", [
    ["check", "all", "--exclude", "smbb"],
    ["check", "all", "--exclude", "ldap,unknown"],
    ["check", "all", "--exclude", "ldap,,smb"],
    ["check", "all", "--exclude", "ldap,"],
    ["check", "all", "--exclude", " "],
    ["check", "all", "--exclude", "ldap", "--exclude", "smb"],
    ["check", "--exclude", "ldap", "all", "--exclude", "smb"],
    ["check", "run", "ldap", "--exclude", "ldap"],
    ["check", "run", "ldap", "not-a-check", "--exclude", "ldap"],
    ["check", "--exclude", "smb", "smb"],
    ["check", "all", "--exclude", ",".join(check.AVAILABLE_CHECKS)],
])
def test_cli_rejects_invalid_or_empty_exclusions_before_running(monkeypatch, args):
    monkeypatch.setattr(check, "run_checks", lambda **_kwargs: pytest.fail("checks ran"))
    monkeypatch.setattr(
        check, "run_selected_checks", lambda *_args, **_kwargs: pytest.fail("checks ran")
    )
    result = CliRunner().invoke(app, args)
    assert result.exit_code != 0
    assert "--exclude" in result.output


@pytest.mark.parametrize("domain", [None, "", "   "])
def test_cli_rejects_missing_domain_before_running_checks(monkeypatch, domain):
    monkeypatch.setattr(check, "require_session", lambda: {"domain": domain})
    monkeypatch.setattr(check, "run_checks", lambda **kwargs: pytest.fail("checks ran"))
    result = CliRunner().invoke(app, ["check", "--csacyber"])
    assert result.exit_code != 0
    assert "requires a domain in session metadata" in result.output


def test_cli_rejects_dc_without_csacyber(monkeypatch):
    monkeypatch.setattr(check, "run_checks", lambda **kwargs: pytest.fail("checks ran"))
    result = CliRunner().invoke(app, ["check", "--dc", "dc.example.com"])
    assert result.exit_code != 0
    assert "--dc requires --csacyber" in result.output


def test_cli_reports_missing_session(monkeypatch):
    def missing_session():
        raise RuntimeError("Run 'ad-kit enum' before executing assessment checks.")

    monkeypatch.setattr(check, "require_session", missing_session)
    result = CliRunner().invoke(app, ["check", "ldap", "--csacyber"])
    assert result.exit_code != 0
    assert "Run 'ad-kit enum'" in result.output
