import json
from html.parser import HTMLParser

import pytest
from typer.testing import CliRunner

from ad_kit.cli import app
from ad_kit.commands import check
from ad_kit.core.finding import Finding
from ad_kit.reporting import html, markdown, results


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
        "# Commentary\n\nFirst line continues.\n\nSecond paragraph.\n\n"
        "### Affected Assets\n\n- host <one>",
        "# Evidence\n\n1. Evidence </textarea><script>alert(1)</script>",
        "# Remediation\n\nFix <issue> & retry.\n\n### References\n\n"
        "- [https://example.com/?a=1&b=2](https://example.com/?a=1&b=2)",
    ]
    assert [(s["title"], s["headings"]) for s in parser.sections] == [
        ("Commentary", ["Affected Assets"]),
        ("Evidence", []),
        ("Remediation", ["References"]),
    ]
    assert parser.copy_texts[0].index("Affected Assets") < parser.copy_texts[0].index("Evidence")
    assert parser.copy_texts[0].index("Remediation") < parser.copy_texts[0].index("References")
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
        "# Remediation\n\n### References\n\n"
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
        "# Commentary\n\n### Affected Assets\n\n- asset",
        markdown.format_findings([second]),
        "# Commentary\n\nOther commentary",
        "# Remediation\n\nOther fix",
    ]


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
    report = (tmp_path / "ad-kit_findings.html").read_text(encoding="utf-8")
    data = json.loads((tmp_path / "ad-kit_findings.json").read_text(encoding="utf-8"))
    assert "SMB-001 - Mapped" in report and "OTHER-001 - Unmapped" in report
    assert [item["id"] for item in data["findings"]] == ["smb-signing-not-enforced"]
    assert list(tmp_path.glob("findings-*.md")) == [old_markdown]
    assert old_markdown.read_text(encoding="utf-8") == "previous report"

    check.run_selected_checks([])
    assert "No findings were generated." in (tmp_path / "ad-kit_findings.html").read_text(
        encoding="utf-8"
    )
    assert json.loads((tmp_path / "ad-kit_findings.json").read_text(encoding="utf-8")) == {
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

    assert "SMB-001 - Mapped" in (tmp_path / "ad-kit_findings.html").read_text(encoding="utf-8")
    assert not list(tmp_path.glob("findings-*.md"))
    assert json.loads((tmp_path / "ad-kit_findings.json").read_text(encoding="utf-8"))[
        "findings"
    ][0]["id"] == "smb-signing-not-enforced"


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
