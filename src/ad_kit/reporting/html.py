"""Self-contained HTML findings report."""

from html import escape
from pathlib import Path

from ad_kit.core.finding import Finding
from ad_kit.reporting.markdown import format_findings, format_paragraphs


def _text_section(title: str, text: str) -> str:
    if not text:
        return ""
    return f"<h3>{title}</h3><div class=\"text\">{escape(text)}</div>"


def _list_section(title: str, items: list[str], *, ordered: bool = False) -> str:
    if not items:
        return ""
    tag = "ol" if ordered else "ul"
    entries = "".join(f"<li>{escape(item)}</li>" for item in items)
    return f"<h3>{title}</h3><{tag}>{entries}</{tag}>"


def render_html(findings: list[Finding]) -> str:
    """Render the complete report without external assets or network access."""
    cards = []
    for finding in findings:
        cards.append(
            '<article class="finding">'
            f"<h2>{escape(finding.id)} - {escape(finding.title)}</h2>"
            '<button type="button" class="copy">Copy Markdown</button> '
            '<span class="status" aria-live="polite"></span>'
            f'<textarea class="copy-text" hidden>{escape(format_findings([finding]))}'
            "</textarea>"
            + _text_section("Commentary", format_paragraphs(finding.commentary))
            + _list_section("Evidence", finding.evidence, ordered=True)
            + _text_section("Remediation", format_paragraphs(finding.remediation))
            + _list_section("Affected Assets", finding.affected_assets)
            + _list_section("References", finding.references)
            + "</article>"
        )
    content = "\n".join(cards) or '<p class="empty">No findings were generated.</p>'
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
    .finding h2 {{ margin-top: 0; }}
    .finding h3 {{ margin-bottom: .4rem; }}
    .text {{ white-space: pre-wrap; line-height: 1.55; }}
    .status, #count, footer {{ color: #53647b; }}
    .copy-buffer {{ position: fixed; left: -9999px; top: 0; }}
  </style>
</head>
<body>
  <header><h1>AD-Kit Findings</h1><p>Local assessment report</p></header>
  <main>
    <label for="search">Search findings</label>
    <input id="search" type="search" placeholder="Search findings">
    <p id="count" aria-live="polite">{len(findings)} findings</p>
    <div id="findings">{content}</div>
    <p id="no-matches" hidden>No findings match the search.</p>
    <footer>This report works offline and contains assessment data.</footer>
  </main>
  <script>
    const cards = [...document.querySelectorAll(".finding")];
    const search = document.getElementById("search");
    search.addEventListener("input", () => {{
      const query = search.value.trim().toLowerCase();
      let visible = 0;
      for (const card of cards) {{
        card.hidden = !card.textContent.toLowerCase().includes(query);
        if (!card.hidden) visible++;
      }}
      document.getElementById("count").textContent = `${{visible}} of ${{cards.length}} findings`;
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

    for (const card of cards) {{
      const button = card.querySelector(".copy");
      const status = card.querySelector(".status");
      button.addEventListener("click", async () => {{
        button.disabled = true;
        status.textContent = "Copying...";
        try {{
          await copyText(card.querySelector(".copy-text").value);
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


def write_report(findings: list[Finding], path: Path) -> None:
    path.write_text(render_html(findings), encoding="utf-8")
