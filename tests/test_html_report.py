import json
from html.parser import HTMLParser

import pytest
from typer.testing import CliRunner

from ad_kit.cli import app
from ad_kit.commands import check
from ad_kit.core.finding import EvidenceTable, Finding
from ad_kit.core.findings import load_finding
from ad_kit.reporting import html, introductions, markdown, results


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.copy_texts = []
        self.links = []
        self.sections = []
        self._in_copy_text = False
        self._in_summary = False
        self._in_h3 = False

    def handle_starttag(self, tag, attrs):
        if tag == "details":
            self.sections.append({"title": "", "headings": []})
        if tag == "summary":
            self._in_summary = True
        if tag == "h3" and self.sections:
            self._in_h3 = True
        if tag == "textarea" and ("class", "copy-text") in attrs:
            self._in_copy_text = True
            self.copy_texts.append("")
        if tag == "a":
            self.links.append(dict(attrs))

    def handle_endtag(self, tag):
        if tag == "textarea":
            self._in_copy_text = False
        if tag == "summary":
            self._in_summary = False
        if tag == "h3":
            self._in_h3 = False

    def handle_data(self, data):
        if self._in_copy_text:
            self.copy_texts[-1] += data
        if self._in_summary:
            self.sections[-1]["title"] += data
        if self._in_h3:
            self.sections[-1]["headings"].append(data)


def test_html_contains_complete_copyable_findings_and_escapes_data():
    finding = Finding(
        id="TEST-001",
        title='<script>alert("title")</script>',
        commentary="First line\ncontinues.\n\nSecond paragraph.",
        remediation="Fix <issue> & retry.",
        evidence=["Evidence </textarea><script>alert(1)</script>"],
        affected_assets=["host <one>"],
        references=["https://example.com/?a=1&b=2"],
    )

    report = html.render_html([finding])
    parser = ReportParser()
    parser.feed(report)

    assert parser.copy_texts == [
        markdown.format_findings([finding]),
        "First line continues.\n\nSecond paragraph.\n\n"
        "### Affected Assets\n\n- host <one>",
        "1. Evidence </textarea><script>alert(1)</script>",
        "Fix <issue> & retry.\n\n### References\n\n"
        "- [https://example.com/?a=1&b=2](https://example.com/?a=1&b=2)",
    ]
    assert [(s["title"], s["headings"]) for s in parser.sections] == [
        ("Commentary", ["Affected Assets"]),
        ("Evidence", []),
        ("Remediation", ["References"]),
    ]
    assert parser.copy_texts[0].index("Affected Assets") < parser.copy_texts[0].index("Evidence")
    assert parser.copy_texts[0].index("Remediation") < parser.copy_texts[0].index("References")
    assert "### Commentary\n\nFirst line continues." in parser.copy_texts[0]
    assert "### Evidence\n\n1. Evidence " in parser.copy_texts[0]
    assert "### Remediation\n\nFix <issue> & retry." in parser.copy_texts[0]
    assert "- [https://example.com/?a=1&b=2](https://example.com/?a=1&b=2)" in parser.copy_texts[0]
    assert "<script>alert" not in report
    assert "&lt;script&gt;" in report
    assert "host &lt;one&gt;" in report
    assert "https://example.com/?a=1&amp;b=2" in report
    assert parser.links == [{
        "href": "https://example.com/?a=1&b=2",
        "target": "_blank",
        "rel": "noopener noreferrer",
    }]


def test_html_evidence_copy_retains_table_and_list_without_heading():
    finding = Finding(
        "TEST-002", "Evidence", "", "",
        evidence=["Additional evidence."],
        evidence_table=EvidenceTable(
            "Detected methods:", ("Host", "Methods"), [("DC|1", "PetitPotam")]
        ),
    )
    parser = ReportParser()
    parser.feed(html.render_html([finding]))

    assert "### Evidence\n\nDetected methods:" in parser.copy_texts[0]
    assert parser.copy_texts[1] == (
        "Detected methods:\n\n| Host | Methods |\n| --- | --- |\n"
        "| DC\\|1 | PetitPotam |\n\n1. Additional evidence."
    )


def test_html_references_only_link_http_urls_and_escape_attributes():
    references = [
        'https://example.com/?q="quoted"&x=1',
        "http://example.org/path",
        "javascript:alert(1)",
        "https://example.com/\nunsafe",
    ]
    finding = Finding("TEST-002", "References", "", "", references=references)
    parser = ReportParser()
    report = html.render_html([finding])
    parser.feed(report)

    assert [link["href"] for link in parser.links] == references[:2]
    assert all(link["target"] == "_blank" for link in parser.links)
    assert "javascript:alert(1)" in report
    assert parser.copy_texts == [
        markdown.format_findings([finding]),
        "### References\n\n"
        + "\n".join(f"- [{reference}]({reference})" for reference in references),
    ]


def test_html_sections_handle_missing_text_and_multiple_findings():
    first = Finding("ONE", "First", "", "", affected_assets=["asset"])
    second = Finding("TWO", "Second", "Other commentary", "Other fix")
    parser = ReportParser()
    parser.feed(html.render_html([first, second]))

    assert [s["title"] for s in parser.sections] == ["Commentary", "Commentary", "Remediation"]
    assert parser.copy_texts == [
        markdown.format_findings([first]),
        "### Affected Assets\n\n- asset",
        markdown.format_findings([second]),
        "Other commentary",
        "Other fix",
    ]


def test_group_introductions_are_copyable_and_describe_only_present_findings():
    findings = [
        load_finding("smb", "SMB-001"),
        load_finding("ldap", "LDAP-003"),
        load_finding("smb", "SMB-004"),
        load_finding("ldap", "LDAP-001"),
    ]
    report = html.render_html(findings)
    parser = ReportParser()
    parser.feed(report)
    smb_intro = parser.copy_texts[0]
    ldap_intro = next(text for text in parser.copy_texts if text.startswith(
        "The assessment identified multiple LDAP security observations"
    ))

    assert "systems not requiring SMB signing" in smb_intro
    assert "write-related permissions reported for a standard user" in smb_intro
    assert "effective file-write access" in smb_intro
    assert "SMBv1" not in smb_intro and "enumeration" not in smb_intro
    assert "anonymous LDAP binds" in ldap_intro
    assert "directory enumeration where separately permitted" in ldap_intro
    assert "channel binding" not in ldap_intro
    assert report.index("SMB overview") < report.index("SMB-001") < report.index("SMB-004")
    assert report.index("SMB-004") < report.index("LDAP overview")
    assert report.index("LDAP overview") < report.index("LDAP-003") < report.index("LDAP-001")
    assert 'introduction.hidden = Boolean(query)' in report


def test_group_introduction_omitted_for_single_findings_and_escapes_unknown_titles():
    first = Finding("CUSTOM-001", "<untrusted>", "", "")
    second = Finding("CUSTOM-002", "Another", "", "")
    assert 'class="group-introduction"' not in html.render_html([first])
    report = html.render_html([first, second])
    parser = ReportParser()
    parser.feed(report)
    assert "the finding '<untrusted>'" in parser.copy_texts[0]
    assert "&lt;untrusted&gt;" in report
    assert "<untrusted>" not in report


def test_smb_introduction_covers_all_observed_findings_without_assuming_dc_scope():
    findings = [load_finding("smb", f"SMB-00{index}") for index in range(1, 5)]
    intro = introductions.group_introduction("SMB", findings)
    assert "systems not requiring SMB signing" in intro
    assert "systems supporting SMBv1" in intro
    assert "empty-credential SMB enumeration" in intro
    assert "write-related permissions reported for a standard user" in intro
    assert "authentication capture and relay where effective file-write access exists" in intro
    assert "domain controllers" not in intro.lower()
    assert "widespread" not in intro


@pytest.mark.parametrize(("category", "ids"), [
    ("smb", ["SMB-001", "SMB-002", "SMB-003", "SMB-004"]),
    ("ldap", ["LDAP-001", "LDAP-002", "LDAP-003"]),
    ("password_policy", ["PASS-001", "PASS-002", "PASS-003"]),
    ("asreproast", ["ASREP-001", "ASREP-002"]),
    ("kerberoast", ["KERB-001", "KERB-002"]),
    ("delegations", ["DELEG-001", "DELEG-002", "DELEG-003"]),
    ("adcs", ["ADCS-ESC1", "ADCS-ESC8", "ADCS-ESC15"]),
    ("privileged_excessive", ["PRIV-001", "PRIV-002", "PRIV-003", "PRIV-004", "PRIV-005"]),
    ("local_admin", ["LA-001", "LA-002"]),
])
def test_supported_multi_finding_topics_have_specific_introductions(category, ids):
    findings = [load_finding(category, finding_id) for finding_id in ids]
    groups = introductions.group_findings(findings)
    assert len(groups) == 1
    introduction = introductions.group_introduction(*groups[0])
    assert "the finding '" not in introduction
    assert "Depending on the circumstances" in introduction


def test_incomplete_checks_are_collapsed_after_findings_and_escaped():
    finding = Finding("TEST-003", "Example", "Comment", "Fix")
    report = html.render_html([finding], ["SMB - host <one>: Unknown", "LDAP - host: Failed"])
    section = '<details class="incomplete"><summary>Incomplete checks (2 entries)</summary>'
    assert section in report
    assert report.index("TEST-003 - Example") < report.index(section) < report.index("<footer>")
    assert "SMB - host &lt;one&gt;: Unknown" in report
    assert "LDAP - host: Failed" in report
    assert 'class="incomplete"' not in html.render_html([finding], [])


def test_html_singular_report_counts():
    finding = Finding("TEST-003", "Example", "Comment", "Fix")
    report = html.render_html([finding], ["SMB: Failed"])
    assert 'aria-live="polite">1 finding</p>' in report
    assert "Incomplete checks (1 entry)" in report
    assert 'cards.length === 1 ? "finding" : "findings"' in report


def test_run_exports_all_findings_without_markdown_files(monkeypatch, tmp_path):
    mapped = Finding("SMB-001", "Mapped", "Comment", "Fix", evidence=["proof"])
    unmapped = Finding("OTHER-001", "Unmapped", "Other", "Fix")
    old_markdown = tmp_path / "findings-old.md"
    old_markdown.write_text("previous report", encoding="utf-8")
    def fake_check(password):
        results.record_findings([mapped, unmapped])
        return password

    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setitem(
        check.AVAILABLE_CHECKS, "test-report", check.CheckDefinition(fake_check, False)
    )

    check.run_selected_checks(["test-report"])
    report = (tmp_path / "ad-kit_findings_test-report.html").read_text(encoding="utf-8")
    data = json.loads((tmp_path / "ad-kit_findings_test-report.json").read_text(encoding="utf-8"))
    assert "SMB-001 - Mapped" in report and "OTHER-001 - Unmapped" in report
    assert [item["id"] for item in data["findings"]] == ["OTHER-001", "SMB-001"]
    assert list(tmp_path.glob("findings-*.md")) == [old_markdown]
    assert old_markdown.read_text(encoding="utf-8") == "previous report"

    check.run_selected_checks([])
    assert "No findings were generated." in (tmp_path / "ad-kit_findings_selected.html").read_text(
        encoding="utf-8"
    )
    assert json.loads((tmp_path / "ad-kit_findings_selected.json").read_text(encoding="utf-8")) == {
        "findings": []
    }


def test_full_run_writes_reports(monkeypatch, tmp_path):
    finding = Finding("SMB-001", "Mapped", "Comment", "Fix")
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    monkeypatch.setattr(
        check, "run_ldap_checks",
        lambda: results.record_findings([finding]),
    )
    monkeypatch.setattr(check, "run_smb_checks", lambda *_: "password")
    monkeypatch.setattr(check, "_run_authed", lambda _name, _check, password: password)

    check.run_checks()

    assert "SMB-001 - Mapped" in (tmp_path / "ad-kit_findings_all.html").read_text(encoding="utf-8")
    assert not list(tmp_path.glob("findings-*.md"))
    assert json.loads((tmp_path / "ad-kit_findings_all.json").read_text(encoding="utf-8"))[
        "findings"
    ][0]["id"] == "SMB-001"


def test_selected_check_reports_preserve_other_runs(monkeypatch, tmp_path):
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    for module in ("ldap", "smb"):
        monkeypatch.setitem(
            check.AVAILABLE_CHECKS, module, check.CheckDefinition(
                lambda password, name=module: (
                    results.record_findings([Finding(name, name, name, "")]), password
                )[1],
                False,
            )
        )
    full_report = tmp_path / "ad-kit_findings_all.html"
    full_xml = tmp_path / "ad-kit_findings_all.xml"
    full_report.write_text("full report", encoding="utf-8")
    full_xml.write_text("full xml", encoding="utf-8")

    check.run_selected_checks(["ldap", "smb"])
    combined = tmp_path / "ad-kit_findings_ldap_smb.html"
    assert "ldap - ldap" in combined.read_text(encoding="utf-8")
    assert "smb - smb" in combined.read_text(encoding="utf-8")
    assert (tmp_path / "ad-kit_findings_ldap_smb.json").exists()
    assert not (tmp_path / "ad-kit_findings_ldap_smb.xml").exists()
    check.run_selected_checks(["ldap"])
    assert (tmp_path / "ad-kit_findings_ldap.html").exists()
    assert combined.exists()
    assert full_report.read_text(encoding="utf-8") == "full report"
    assert full_xml.read_text(encoding="utf-8") == "full xml"


def test_excluded_checks_are_not_in_report_filename(monkeypatch, tmp_path):
    monkeypatch.setattr(check, "get_artefacts_dir", lambda: tmp_path)
    for module in ("ldap", "smb"):
        monkeypatch.setitem(
            check.AVAILABLE_CHECKS, module, check.CheckDefinition(lambda password: password, False)
        )

    result = CliRunner().invoke(app, ["check", "run", "ldap", "smb", "--exclude", "smb"])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "ad-kit_findings_ldap.html").exists()
    assert not (tmp_path / "ad-kit_findings_ldap_smb.html").exists()


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["check"], "all"),
        (["check", "all"], "all"),
        (["check", "ldap"], ["ldap"]),
        (["check", "run", "ldap", "smb"], ["ldap", "smb"]),
    ],
)
def test_cli_dispatches_checks(monkeypatch, args, expected):
    calls = []
    monkeypatch.setattr(check, "run_checks", lambda: calls.append("all"))
    monkeypatch.setattr(
        check,
        "run_selected_checks",
        lambda modules: calls.append(modules),
    )

    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert calls == [expected]


@pytest.mark.parametrize("args", [["check", "--markdown"], ["check", "ldap", "--markdown"]])
def test_cli_rejects_removed_markdown_option(args):
    result = CliRunner().invoke(app, args)
    assert result.exit_code != 0
    assert "No such option: --markdown" in result.output
