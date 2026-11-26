import json
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import dns.resolver
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


def test_sureformat_export_assigns_findings_to_affected_hosts(monkeypatch, tmp_path):
    findings = [
        Finding("SMB-001", "SMB", "SMB signing details.", "",
                affected_assets=["DC02.EXAMPLE.COM", "HOST01.EXAMPLE.COM"]),
        Finding("SMB-002", "SMBv1", "SMBv1 details.", "",
                affected_assets=["HOST01.EXAMPLE.COM"]),
        Finding("SMB-003", "SMB", "Anonymous enumeration.", "",
                affected_assets=["DC01.EXAMPLE.COM"]),
        Finding("SMB-004", "SMB", "Writable shares.", "",
                affected_assets=["HOST01.EXAMPLE.COM"]),
        Finding("LDAP-001", "LDAP", "LDAP signing details.", "",
                affected_assets=["DC01.EXAMPLE.COM", "dc02.example.com."]),
        Finding("LDAP-002", "LDAP", "Channel binding details.", "",
                affected_assets=["DC01.EXAMPLE.COM"]),
        Finding("LDAP-003", "LDAP", "Anonymous bind details.", "",
                affected_assets=["DC01.EXAMPLE.COM"]),
        Finding("NOPAC-001", "NoPAC", "NoPAC details.", "",
                affected_assets=["192.0.2.2"]),
        Finding("OTHER-001", "Unmapped", "Other details.", ""),
        Finding("PRIV-001", "Privileged accounts", "Privilege details.", ""),
        Finding("PRIV-002", "Protected accounts", "Protected details.", ""),
        Finding("LA-002", "Local admin", "DC access.", "", affected_assets=["dc01"]),
    ]
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(check, "require_session", lambda: {
        "domain": "EXAMPLE.COM", "dc_hostnames": ["DC01.EXAMPLE.COM", "DC02.EXAMPLE.COM"],
        "dc_ips": ["192.0.2.1", "192.0.2.2"], "dc_ip": "192.0.2.1",
    })
    monkeypatch.setattr(sureformat, "_resolve_host", lambda *_args: "192.0.2.3")
    monkeypatch.setitem(
        check.AVAILABLE_CHECKS,
        "fake",
        check.CheckDefinition(lambda password: results.record_findings(findings), False),
    )

    check.run_selected_checks(["fake"], csacyber=True)

    root, item, service, vulnerabilities = _vulnerabilities(tmp_path / "ad-kit_findings_fake.xml")
    assert root.attrib == {"source": "SureFormat", "version": "1.0.0"}
    assert item.attrib == {"ipaddress": "", "hostname": "example.com"}
    assert service.attrib == {"name": "", "port": "", "protocol": "tcp"}
    assert [v.attrib["id"] for v in vulnerabilities] == ["SC-10674", "SC-10700"]
    protected = next(v for v in vulnerabilities if v.attrib["id"] == "SC-10700")
    assert protected.findtext("information") == "Protected details."
    assert (tmp_path / "ad-kit_findings_fake.html").exists()
    assert not (tmp_path / "ad-kit_findings_fake.json").exists()
    dc1, dc2, host = root.findall("item")[1:]
    assert dc1.attrib == {"hostname": "DC01.EXAMPLE.COM", "ipaddress": "192.0.2.1"}
    assert dc2.attrib == {"hostname": "DC02.EXAMPLE.COM", "ipaddress": "192.0.2.2"}
    assert host.attrib == {"hostname": "HOST01.EXAMPLE.COM", "ipaddress": "192.0.2.3"}
    def services(item):
        return {
            (service.attrib["name"], service.attrib["port"], service.attrib["protocol"]):
            [v.attrib["id"] for v in service.findall("./vulnerabilities/vulnerability")]
            for service in item.findall("./services/service")
        }

    assert services(dc1) == {
        ("", "", "tcp"): ["SC-6642"],
        ("ldap", "389", "tcp"): ["SC-6080", "SC-1000"],
        ("ldaps", "636", "tcp"): ["SC-6643"],
        ("smb", "445", "tcp"): ["SC-1909"],
    }
    assert services(dc2) == {
        ("ldap", "389", "tcp"): ["SC-6080"],
        ("", "", "tcp"): ["SC-3704"],
        ("smb", "445", "tcp"): ["SC-7704"],
    }
    assert services(host) == {
        ("smb", "445", "tcp"): ["SC-7704", "SC-3576", "SC-7367"],
    }
    assert not (tmp_path / "ad-kit_findings_fake-dc.xml").exists()


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


def test_sureformat_combines_matching_ids_only_within_the_same_service(monkeypatch, tmp_path):
    monkeypatch.setitem(sureformat.FINDING_MAP, "SMB-002", "SC-7704")
    monkeypatch.setitem(sureformat.FINDING_MAP, "LDAP-001", "SC-7704")
    path = tmp_path / "test.xml"
    sureformat.write_findings(
        path, "example.com", [],
        controllers=[("dc.example.com", "192.0.2.1")],
        host_findings=[
            Finding("SMB-001", "SMB signing", "Signing.", "", affected_assets=["dc"]),
            Finding("SMB-002", "SMBv1", "SMBv1.", "", affected_assets=["dc"]),
            Finding("LDAP-001", "LDAP signing", "LDAP.", "", affected_assets=["dc"]),
        ],
    )
    item = ET.parse(path).getroot().findall("item")[1]
    smb = item.find("./services/service[@port='445']/vulnerabilities")
    ldap = item.find("./services/service[@port='389']/vulnerabilities")
    assert len(smb) == 1
    assert smb.find("vulnerability").attrib["id"] == "SC-7704"
    assert smb.findtext("vulnerability/information") == "Signing.\nSMBv1."
    assert len(ldap) == 1
    assert ldap.find("vulnerability").attrib["id"] == "SC-7704"
    assert ldap.findtext("vulnerability/information") == "LDAP."


def test_sureformat_exports_builtin_administrator_finding(tmp_path):
    path = tmp_path / "test.xml"
    sureformat.write_findings(path, "example.test", [
        {"id": "PRIV-004", "description": "Built-in Administrator enabled."},
    ])
    _, _, _, vulnerabilities = _vulnerabilities(path)
    assert [v.attrib["id"] for v in vulnerabilities] == ["SC-4958"]
    assert vulnerabilities[0].findtext("information") == "Built-in Administrator enabled."


@pytest.mark.parametrize("session", [
    {"dc_hostnames": ["dc1"], "dc_ips": []},
    {"dc_controllers": [{"hostname": "dc1", "ip": "not-an-ip"}]},
    {"dc_controllers": [
        {"hostname": "dc1.example.com", "ip": "192.0.2.1"},
        {"hostname": "dc2.example.com", "ip": "192.0.2.1"},
    ]},
])
def test_rejects_unreliable_dc_inventory(session):
    with pytest.raises(sureformat.DCExportError):
        sureformat.dc_inventory(session)


@pytest.mark.parametrize("asset", ["unknown.example.com", "shared"])
def test_export_warns_and_uses_hostname_for_unresolved_or_ambiguous_assets(
    monkeypatch, tmp_path, asset
):
    path = tmp_path / "report.xml"
    warnings = []
    monkeypatch.setattr(sureformat, "print_warning", warnings.append)
    sureformat.write_findings(
        path, "example.com", [],
        controllers=[("shared.example.com", "192.0.2.1"), ("shared.other.com", "192.0.2.2")],
        host_findings=[Finding("LDAP-001", "LDAP", "", "", affected_assets=[asset])],
    )
    item = ET.parse(path).getroot().findall("item")[1]
    assert item.attrib == {"hostname": asset, "ipaddress": ""}
    assert [v.attrib["id"] for v in item.findall(".//vulnerability")] == ["SC-6080"]
    assert item.find("./services/service").attrib == {
        "name": "ldap", "port": "389", "protocol": "tcp",
    }
    assert len(warnings) == 1


def test_dc_export_normalises_ip_and_omits_unaffected_controllers(tmp_path):
    path = tmp_path / "report.xml"
    sureformat.write_findings(
        path, "example.com", [],
        controllers=[("dc1.example.com", "2001:db8::1"), ("dc2.example.com", "192.0.2.2")],
        host_findings=[
            Finding("NOPAC-001", "NoPAC", "", "", affected_assets=["2001:0db8:0:0::1"])
        ],
    )
    items = ET.parse(path).getroot().findall("item")
    assert [item.attrib for item in items] == [
        {"hostname": "example.com", "ipaddress": ""},
        {"hostname": "dc1.example.com", "ipaddress": "2001:db8::1"},
    ]


@pytest.mark.parametrize(("addresses", "expected"), [
    (["192.0.2.3"], "192.0.2.3"),
    (["2001:db8::1"], "2001:db8::1"),
    (["192.0.2.3", "192.0.2.4"], None),
    (["192.0.2.3", "2001:db8::1"], None),
])
def test_host_resolution_uses_dc_dns_and_rejects_multiple_addresses(
    monkeypatch, addresses, expected
):
    class FakeResolver:
        def __init__(self, *, configure):
            assert configure is False
            self.nameservers = []
            self.timeout = 0
            self.lifetime = 0

        def resolve(self, name, kind, *, search):
            assert self.nameservers == ["192.0.2.1"]
            assert name == "host.example.com"
            assert search is False
            result = [SimpleNamespace(address=address) for address in addresses
                      if (":" in address) == (kind == "AAAA")]
            if not result:
                raise dns.resolver.NoAnswer
            return result

    monkeypatch.setattr(sureformat.dns.resolver, "Resolver", FakeResolver)
    if expected is None:
        with pytest.raises(ValueError, match="DNS returned 2 IP addresses"):
            sureformat._resolve_host("host", "example.com", "192.0.2.1")
    else:
        assert sureformat._resolve_host("host", "example.com", "192.0.2.1") == expected


def test_host_export_does_not_assign_shared_ip_to_different_hosts(monkeypatch, tmp_path):
    warnings = []
    monkeypatch.setattr(sureformat, "print_warning", warnings.append)
    monkeypatch.setattr(sureformat, "_resolve_host", lambda *_args: "192.0.2.1")
    path = tmp_path / "report.xml"
    sureformat.write_findings(
        path, "example.com", [],
        controllers=[("dc.example.com", "192.0.2.1")],
        host_findings=[
            Finding("SMB-001", "SMB", "", "",
                    affected_assets=["dc.example.com", "host.example.com"]),
        ],
    )
    dc, host = ET.parse(path).getroot().findall("item")[1:]
    assert dc.attrib == {"hostname": "dc.example.com", "ipaddress": "192.0.2.1"}
    assert host.attrib == {"hostname": "host.example.com", "ipaddress": ""}
    assert any("matches multiple hosts" in warning for warning in warnings)


def test_host_finding_without_affected_hosts_warns_and_remains_in_domain(monkeypatch, tmp_path):
    warnings = []
    monkeypatch.setattr(results, "print_warning", warnings.append)
    results.reset()
    results.record_findings([Finding("SMB-001", "SMB", "Details.", "")])
    results.write_reports(tmp_path, domain="example.com", session={})
    _, _, _, vulnerabilities = _vulnerabilities(tmp_path / "ad-kit_findings_all.xml")
    assert [v.attrib["id"] for v in vulnerabilities] == ["SC-7704"]
    assert any("no affected hosts" in warning for warning in warnings)


def test_cli_exports_unmatched_dc_finding_by_hostname(monkeypatch, tmp_path):
    monkeypatch.setattr(util, "ARTEFACTS_DIR", tmp_path)
    monkeypatch.setattr(check, "require_session", lambda: {
        "domain": "example.com", "dc_hostnames": ["dc1.example.com"], "dc_ips": ["192.0.2.1"]
    })
    monkeypatch.setitem(
        check.AVAILABLE_CHECKS, "ldap",
        check.CheckDefinition(
            lambda password: results.record_findings([
                Finding("LDAP-001", "LDAP", "", "", affected_assets=["dc2.example.com"])
            ]), False,
        ),
    )
    result = CliRunner().invoke(app, ["check", "ldap", "--csacyber"])
    assert result.exit_code == 0, result.output
    item = ET.parse(tmp_path / "ad-kit_findings_ldap.xml").getroot().findall("item")[1]
    assert item.attrib == {"hostname": "dc2.example.com", "ipaddress": ""}
    assert "Cannot determine IP" in result.output


def test_full_run_exports_xml_without_replacing_previous_json(monkeypatch, tmp_path):
    previous_json = tmp_path / "ad-kit_findings_all.json"
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

    _, _, _, vulnerabilities = _vulnerabilities(tmp_path / "ad-kit_findings_all.xml")
    assert [v.attrib["id"] for v in vulnerabilities] == ["SC-6643"]
    assert previous_json.read_text(encoding="utf-8") == "previous output"


def test_cli_creates_single_xml_with_domain_and_dc_items(monkeypatch, tmp_path):
    (tmp_path / "session.json").write_text(json.dumps({
        "domain": "example.com",
        "dc_controllers": [
            {"hostname": "DC1.example.com", "ip": "192.0.2.1"},
            {"hostname": "DC2.example.com", "ip": "192.0.2.2"},
        ],
    }), encoding="utf-8")
    monkeypatch.setattr(util, "ARTEFACTS_DIR", tmp_path)
    monkeypatch.setitem(
        check.AVAILABLE_CHECKS,
        "ldap",
        check.CheckDefinition(
            lambda password: results.record_findings([
                Finding("LDAP-003", "LDAP", "", "", affected_assets=["dc1"]),
                Finding("COERCE-001", "Coercion", "", "",
                        affected_assets=["DC2", "dc1.example.com"]),
            ]),
            False,
        ),
    )

    result = CliRunner().invoke(app, ["check", "ldap", "--csacyber"])

    assert result.exit_code == 0, result.output
    root, domain_item, _, domain_vulnerabilities = _vulnerabilities(
        tmp_path / "ad-kit_findings_ldap.xml"
    )
    assert domain_item.attrib["hostname"] == "example.com"
    assert not domain_vulnerabilities
    dc1, dc2 = root.findall("item")[1:]
    assert dc1.attrib == {"hostname": "DC1.example.com", "ipaddress": "192.0.2.1"}
    assert [v.attrib["id"] for v in dc1.findall(".//vulnerability")] == ["SC-9018", "SC-1000"]
    assert dc2.attrib == {"hostname": "DC2.example.com", "ipaddress": "192.0.2.2"}
    assert [v.attrib["id"] for v in dc2.findall(".//vulnerability")] == ["SC-9018"]
    assert not (tmp_path / "ad-kit_findings_ldap-dc.xml").exists()


def test_selected_checks_xml_uses_all_selected_names(monkeypatch, tmp_path):
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(check, "require_session", lambda: {"domain": "example.com"})
    for module, finding_id in (("ldap", "LDAP-001"), ("smb", "SMB-001")):
        monkeypatch.setitem(
            check.AVAILABLE_CHECKS, module, check.CheckDefinition(
                lambda password, name=finding_id: (
                    results.record_findings([Finding(name, name, name, "")]), password
                )[1],
                False,
            )
        )

    check.run_selected_checks(["ldap", "smb"], csacyber=True)
    assert (tmp_path / "ad-kit_findings_ldap_smb.html").exists()
    _, _, _, vulnerabilities = _vulnerabilities(tmp_path / "ad-kit_findings_ldap_smb.xml")
    assert [v.attrib["id"] for v in vulnerabilities] == ["SC-6080", "SC-7704"]
    assert not (tmp_path / "ad-kit_findings_ldap_smb.json").exists()


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["check", "--csacyber"], None),
        (["check", "all", "--csacyber"], None),
        (["check", "--csacyber", "ldap"], ["ldap"]),
        (["check", "run", "ldap", "smb", "--csacyber"], ["ldap", "smb"]),
        (["check", "run", "pass-pol,dns", "--csacyber", "--workers", "16"],
         ["pass-pol", "dns"]),
        (["check", "--csacyber", "run", "ldap"], ["ldap"]),
    ],
)
def test_cli_dispatches_sureformat_options(monkeypatch, args, expected):
    calls = []
    monkeypatch.setattr(check, "require_session", lambda: {
        "domain": "example.com", "dc_hostnames": ["dc.example.com"], "dc_ips": ["192.0.2.1"]
    })
    monkeypatch.setattr(
        check, "run_checks", lambda **kwargs: calls.append((None, kwargs))
    )
    monkeypatch.setattr(
        check, "run_selected_checks", lambda modules, **kwargs: calls.append((modules, kwargs))
    )

    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert calls == [(expected, {"csacyber": True})]


@pytest.mark.parametrize(
    ("args", "expected_workers"),
    [
        (["check"], 4),
        (["check", "--workers", "2"], 2),
        (["check", "all", "--workers", "16"], 16),
        (["check", "--workers", "3", "ldap"], 3),
        (["check", "smb", "--workers", "1"], 1),
        (["check", "run", "ldap", "smb", "--workers", "2"], 2),
        (["check", "run", "pass-pol,dns", "--workers", "16"], 16),
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
        (["check", "run", "ldap,smb", "--exclude", "ldap"], ["smb"], set()),
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
        "all", "--csacyber",
    ],
    [
        "check", "all", "--csacyber",
        "--workers", "8", "--exclude", "ldap,smb",
    ],
])
def test_cli_exclusions_combine_with_export_and_worker_options(monkeypatch, args):
    calls = []
    monkeypatch.setattr(check, "require_session", lambda: {
        "domain": "example.com", "dc_hostnames": ["dc.example.com"], "dc_ips": ["192.0.2.1"]
    })
    monkeypatch.setattr(
        check, "run_checks",
        lambda **kwargs: calls.append((util._check_workers.get(), kwargs)),
    )
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert calls == [(8, {
        "csacyber": True, "exclude": {"ldap", "smb"},
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


@pytest.mark.parametrize("args", [
    ["check", "--dc"],
    ["check", "ldap", "--csacyber", "--dc", "old-group-name"],
    ["check", "--csacyber", "--dc", "ldap", "--dc"],
])
def test_cli_rejects_removed_dc_flag(monkeypatch, args):
    monkeypatch.setattr(check, "require_session", lambda: {
        "domain": "example.com", "dc_hostnames": ["dc.example.com"], "dc_ips": ["192.0.2.1"]
    })
    monkeypatch.setattr(check, "run_selected_checks", lambda *_args, **_kwargs: pytest.fail(
        "checks ran"
    ))
    result = CliRunner().invoke(app, args)
    assert result.exit_code != 0


def test_cli_reports_missing_session(monkeypatch):
    def missing_session():
        raise RuntimeError("Run 'ad-kit enum' before executing assessment checks.")

    monkeypatch.setattr(check, "require_session", missing_session)
    result = CliRunner().invoke(app, ["check", "ldap", "--csacyber"])
    assert result.exit_code != 0
    assert "Run 'ad-kit enum'" in result.output
