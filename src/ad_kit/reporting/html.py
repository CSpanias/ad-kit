"""Self-contained HTML findings report."""

import re
from html import escape
from pathlib import Path

from ad_kit.core.finding import Finding
from ad_kit.core.util import count_form
from ad_kit.reporting.introductions import group_findings, group_introduction, group_title
from ad_kit.reporting.markdown import format_finding_sections, format_findings, format_paragraphs


def _copy_controls(markdown: str, label: str) -> str:
    return (
        '<div class="copy-controls">'
        f'<button type="button" class="copy" aria-label="Copy {label} Markdown">'
        "Copy Markdown</button> "
        '<span class="status" aria-live="polite"></span>'
        f'<textarea class="copy-text" hidden>{escape(markdown)}</textarea>'
        "</div>"
    )


def _list_section(title: str, items: list[str], *, ordered: bool = False) -> str:
    if not items:
        return ""
    tag = "ol" if ordered else "ul"
    entries = "".join(f"<li>{escape(item)}</li>" for item in items)
    heading = f"<h3>{title}</h3>" if title else ""
    return f"{heading}<{tag}>{entries}</{tag}>"


def _references_section(references: list[str]) -> str:
    if not references:
        return ""
    entries = []
    for reference in references:
        text = escape(reference)
        if re.fullmatch(r"https?://[^\s\x00-\x1f\x7f\\]+", reference, re.IGNORECASE):
            text = f'<a href="{text}" target="_blank" rel="noopener noreferrer">{text}</a>'
        entries.append(f"<li>{text}</li>")
    return f"<h3>References</h3><ul>{''.join(entries)}</ul>"


def _render_finding(finding: Finding) -> str:
    sections = format_finding_sections(finding)
    details = []
    for label, markdown in sections.items():
        if label == "Commentary":
            body = (
                f'<div class="text">{escape(format_paragraphs(finding.commentary))}</div>'
                + (
                    f'<p><strong>Note:</strong> '
                    f'{escape(format_paragraphs(finding.commentary_note))}</p>'
                    if finding.commentary_note else ""
                )
                + (
                    _list_section("Affected Assets", finding.affected_assets)
                    if finding.show_affected_assets else ""
                )
            )
        elif label == "Evidence":
            body = (
                f"<p>{escape(finding.evidence_introduction)}</p>"
                if finding.evidence_introduction else ""
            )
            if finding.evidence_table:
                table = finding.evidence_table
                headers = "".join(f"<th>{escape(value)}</th>" for value in table.columns)
                rows = "".join(
                    "<tr>" + "".join(f"<td>{escape(value)}</td>" for value in row) + "</tr>"
                    for row in table.rows
                )
                body += (
                    f"<p>{escape(table.introduction)}</p>"
                    '<div class="table-container"><table>'
                    f"<thead><tr>{headers}</tr></thead><tbody>{rows}</tbody>"
                    "</table></div>"
                )
            body += _list_section("", finding.evidence, ordered=True)
        else:
            body = (
                f'<div class="text">{escape(format_paragraphs(finding.remediation))}</div>'
                + _references_section(finding.references)
            )
        markdown = markdown.partition("\n\n")[2]
        details.append(
            f"<details><summary>{label}</summary>"
            + _copy_controls(markdown, label)
            + body
            + "</details>"
        )
    return (
        '<article class="finding">'
        f"<h2>{escape(finding.id)} - {escape(finding.title)}</h2>"
        + _copy_controls(format_findings([finding]), "finding")
        + "".join(details)
        + "</article>"
    )


def render_html(findings: list[Finding], incomplete: list[str] | None = None) -> str:
    """Render the complete report without external assets or network access."""
    content_parts = []
    for topic, group in group_findings(findings):
        if len(group) > 1:
            introduction = group_introduction(topic, group)
            title = escape(group_title(topic))
            content_parts.append(
                '<section class="group-introduction">'
                f"<h2>{title} overview</h2>"
                + _copy_controls(introduction, f"{title} overview")
                + f'<div class="text">{escape(introduction)}</div></section>'
            )
        content_parts.extend(_render_finding(finding) for finding in group)
    content = "\n".join(content_parts) or '<p class="empty">No findings were generated.</p>'
    finding_label = count_form(len(findings), "finding", "findings")
    incomplete_section = (
        '<details class="incomplete">'
        f"<summary>Incomplete checks ({len(incomplete)} "
        f"{count_form(len(incomplete), 'entry', 'entries')})</summary>"
        "<p>Results do not cover the following checks or hosts:</p>"
        + _list_section("", incomplete)
        + "</details>"
        if incomplete else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AD-Kit Findings</title>
  <style>
    :root {{ font-family: system-ui, sans-serif; color: #172033; background: #f3f6fa; }}
    body {{ margin: 0; }}
    header {{
      padding: 2rem max(1rem, calc((100% - 1100px) / 2));
      background: #10233f; color: white;
    }}
    header h1 {{ margin: 0; }}
    main {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
    input, button {{
      padding: .6rem; border: 1px solid #9aa8bb; border-radius: .35rem;
      background: white; color: inherit;
    }}
    input {{ width: min(100%, 30rem); box-sizing: border-box; }}
    button {{ cursor: pointer; }}
    .finding {{
      background: white; border: 1px solid #dce3ed; border-left: 5px solid #607d9d;
      border-radius: .6rem; margin: 1rem 0; padding: 1rem; overflow-wrap: anywhere;
    }}
    .group-introduction {{
      background: white; border: 1px solid #dce3ed; border-radius: .6rem;
      margin: 1rem 0; padding: 1rem; overflow-wrap: anywhere;
    }}
    .group-introduction h2 {{ margin-top: 0; }}
    .finding h2 {{ margin-top: 0; }}
    .finding h3 {{ margin-bottom: .4rem; }}
    .finding details {{
      margin: .75rem 0; padding: 1rem; border: 1px solid #dce3ed; border-radius: .6rem;
    }}
    .finding summary {{ cursor: pointer; font-weight: 650; }}
    .copy-controls {{ margin: .75rem 0; }}
    .text {{ white-space: pre-wrap; line-height: 1.55; }}
    .table-container {{ overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #dce3ed; padding: .5rem; text-align: left; }}
    .status, #count, footer {{ color: #53647b; }}
    .copy-buffer {{ position: fixed; left: -9999px; top: 0; }}
    .incomplete {{
      background: #fff3cd; border: 1px solid #d5a500; border-radius: .6rem;
      margin: 1rem 0; padding: 1rem; overflow-wrap: anywhere;
    }}
    .incomplete summary {{ cursor: pointer; font-weight: 650; }}
  </style>
</head>
<body>
  <header><h1>AD-Kit Findings</h1><p>Local assessment report</p></header>
  <main>
    <label for="search">Search findings</label>
    <input id="search" type="search" placeholder="Search findings">
    <p id="count" aria-live="polite">{len(findings)} {finding_label}</p>
    <div id="findings">{content}</div>
    <p id="no-matches" hidden>No findings match the search.</p>
    {incomplete_section}
    <footer>This report works offline and contains assessment data.</footer>
  </main>
  <script>
    const cards = [...document.querySelectorAll(".finding")];
    const introductions = [...document.querySelectorAll(".group-introduction")];
    const search = document.getElementById("search");
    search.addEventListener("input", () => {{
      const query = search.value.trim().toLowerCase();
      for (const introduction of introductions) introduction.hidden = Boolean(query);
      let visible = 0;
      for (const card of cards) {{
        card.hidden = !card.textContent.toLowerCase().includes(query);
        if (!card.hidden) visible++;
      }}
      const findingLabel = cards.length === 1 ? "finding" : "findings";
      document.getElementById("count").textContent =
        `${{visible}} of ${{cards.length}} ${{findingLabel}}`;
      document.getElementById("no-matches").hidden = visible > 0 || !cards.length;
    }});

    async function copyText(text) {{
      if (navigator.clipboard?.writeText && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return;
      }}
      const buffer = document.createElement("textarea");
      buffer.value = text;
      buffer.className = "copy-buffer";
      document.body.append(buffer);
      buffer.select();
      let copied;
      try {{
        copied = document.execCommand("copy");
      }} finally {{
        buffer.remove();
      }}
      if (!copied) throw new Error("Clipboard access is unavailable.");
    }}

    for (const controls of document.querySelectorAll(".copy-controls")) {{
      const button = controls.querySelector(".copy");
      const status = controls.querySelector(".status");
      button.addEventListener("click", async () => {{
        button.disabled = true;
        status.textContent = "Copying...";
        try {{
          await copyText(controls.querySelector(".copy-text").value);
          status.textContent = "Copied Markdown to clipboard.";
        }} catch {{
          status.textContent = "Copy failed. Select and copy the text manually.";
        }} finally {{
          button.disabled = false;
        }}
      }});
    }}
  </script>
</body>
</html>
"""


def write_report(
    findings: list[Finding], path: Path, incomplete: list[str] | None = None
) -> None:
    path.write_text(render_html(findings, incomplete), encoding="utf-8")
