#!/usr/bin/env python3
"""
SMP V9.5 — Thesis PDF Generator
Converts SMP_THESIS_V9.5.md to a professional PDF using WeasyPrint.
"""

import os
import sys
import subprocess

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
THESIS_MD = os.path.join(BASE_DIR, "docs", "thesis", "SMP_THESIS_V9.5.md")
THESIS_PDF = os.path.join(BASE_DIR, "docs", "thesis", "SMP_THESIS_V9.5.pdf")

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,300;8..60,400;8..60,600;8..60,700&family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;500;600&display=swap');

@page {
    size: A4;
    margin: 2.5cm 2.2cm 2.5cm 2.5cm;
    @bottom-center {
        content: "SMP V9.5 — Security Management Platform  ·  P R Abinraj  ·  " counter(page);
        font-family: 'Inter', sans-serif;
        font-size: 9pt;
        color: #6b7280;
    }
    @top-right {
        content: "Confidential — Project Submission";
        font-family: 'Inter', sans-serif;
        font-size: 8pt;
        color: #9ca3af;
    }
}

@page :first {
    @bottom-center { content: none; }
    @top-right { content: none; }
}

* {
    box-sizing: border-box;
}

body {
    font-family: 'Source Serif 4', 'Georgia', serif;
    font-size: 11pt;
    line-height: 1.75;
    color: #1a1a2e;
    background: white;
    margin: 0;
    padding: 0;
}

/* Cover page */
.cover {
    page-break-after: always;
    text-align: center;
    padding: 4cm 1cm;
    border-bottom: 3px solid #1e3a5f;
}

h1 {
    font-family: 'Inter', sans-serif;
    font-size: 22pt;
    font-weight: 700;
    color: #1e3a5f;
    line-height: 1.3;
    margin-top: 2em;
    margin-bottom: 0.4em;
    page-break-after: avoid;
}

h2 {
    font-family: 'Inter', sans-serif;
    font-size: 16pt;
    font-weight: 600;
    color: #1e3a5f;
    margin-top: 2.2em;
    margin-bottom: 0.6em;
    padding-bottom: 0.2em;
    border-bottom: 2px solid #e2e8f0;
    page-break-after: avoid;
}

h3 {
    font-family: 'Inter', sans-serif;
    font-size: 13pt;
    font-weight: 600;
    color: #2d4a6b;
    margin-top: 1.6em;
    margin-bottom: 0.4em;
    page-break-after: avoid;
}

h4 {
    font-family: 'Inter', sans-serif;
    font-size: 11pt;
    font-weight: 600;
    color: #374151;
    margin-top: 1.2em;
    margin-bottom: 0.3em;
    page-break-after: avoid;
}

p {
    margin: 0.6em 0 0.9em 0;
    text-align: justify;
    orphans: 3;
    widows: 3;
}

/* Code blocks */
pre {
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 8.5pt;
    line-height: 1.5;
    background: #f1f5f9;
    border: 1px solid #cbd5e1;
    border-left: 4px solid #1e3a5f;
    border-radius: 4px;
    padding: 1em 1.2em;
    margin: 1em 0;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    page-break-inside: avoid;
}

code {
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 8.5pt;
    background: #f1f5f9;
    border: 1px solid #e2e8f0;
    border-radius: 3px;
    padding: 0.15em 0.4em;
    color: #1e3a5f;
}

pre code {
    background: none;
    border: none;
    padding: 0;
    color: inherit;
}

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 1.2em 0;
    font-size: 9.5pt;
    page-break-inside: avoid;
}

thead {
    background: #1e3a5f;
    color: white;
}

th {
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    padding: 0.6em 0.8em;
    text-align: left;
    font-size: 9pt;
    letter-spacing: 0.02em;
}

td {
    padding: 0.5em 0.8em;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: top;
}

tr:nth-child(even) td {
    background: #f8fafc;
}

tr:hover td {
    background: #f0f4f8;
}

/* Lists */
ul, ol {
    margin: 0.6em 0 0.9em 0;
    padding-left: 1.8em;
}

li {
    margin-bottom: 0.25em;
    line-height: 1.65;
}

li > ul, li > ol {
    margin: 0.2em 0;
}

/* Blockquotes */
blockquote {
    margin: 1em 0;
    padding: 0.8em 1.2em;
    background: #f0f4ff;
    border-left: 4px solid #4169e1;
    border-radius: 0 4px 4px 0;
    font-style: italic;
    color: #374151;
}

/* Horizontal rules */
hr {
    border: none;
    border-top: 2px solid #e2e8f0;
    margin: 2em 0;
}

/* Strong and emphasis */
strong {
    font-weight: 700;
    color: #111827;
}

em {
    font-style: italic;
}

/* Links */
a {
    color: #1e3a5f;
    text-decoration: none;
}

/* Page break helpers */
.page-break {
    page-break-after: always;
}

/* Abstract styling */
.abstract {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 1.5em 2em;
    margin: 1.5em 0;
}

/* Chapter numbers */
h1.chapter {
    color: #1e3a5f;
    border-top: 3px solid #1e3a5f;
    padding-top: 0.8em;
}
"""

def read_thesis_md():
    """Read the thesis markdown file."""
    with open(THESIS_MD, "r", encoding="utf-8") as f:
        return f.read()


def strip_yaml_frontmatter(content):
    """Remove YAML frontmatter from markdown."""
    if content.startswith("---"):
        end = content.find("---", 3)
        if end > 0:
            return content[end + 3:].lstrip()
    return content


def md_to_html(md_content):
    """Convert markdown to HTML using Python markdown."""
    try:
        import markdown
        extensions = [
            "tables",
            "fenced_code",
            "codehilite",
            "toc",
            "attr_list",
            "def_list",
            "abbr",
            "md_in_html",
        ]
        md = markdown.Markdown(extensions=extensions)
        return md.convert(md_content)
    except Exception as e:
        print(f"  Markdown conversion warning: {e}")
        # Fallback: basic conversion
        import html
        lines = []
        in_code = False
        for line in md_content.split("\n"):
            if line.startswith("```"):
                if in_code:
                    lines.append("</pre>")
                    in_code = False
                else:
                    lines.append("<pre><code>")
                    in_code = True
            elif in_code:
                lines.append(html.escape(line))
            elif line.startswith("# "):
                lines.append(f"<h1>{html.escape(line[2:])}</h1>")
            elif line.startswith("## "):
                lines.append(f"<h2>{html.escape(line[3:])}</h2>")
            elif line.startswith("### "):
                lines.append(f"<h3>{html.escape(line[4:])}</h3>")
            elif line.startswith("#### "):
                lines.append(f"<h4>{html.escape(line[5:])}</h4>")
            elif line.strip() == "---":
                lines.append("<hr>")
            else:
                lines.append(f"<p>{html.escape(line)}</p>" if line.strip() else "")
        return "\n".join(lines)


def build_html(body_html):
    """Wrap HTML body in a full HTML document with CSS."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Management Platform V9.5 — Academic Thesis</title>
<style>
{CSS}
</style>
</head>
<body>
<div class="cover">
  <div style="margin-bottom: 3em;">
    <div style="font-family: 'JetBrains Mono', monospace; font-size: 9pt; color: #6b7280; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 1em;">
      Project Submission — Computer Science / Information Security
    </div>
    <h1 style="font-size: 24pt; margin-bottom: 0.3em; border: none;">Security Management Platform</h1>
    <h1 style="font-size: 20pt; color: #4169e1; margin-top: 0; border: none;">Version 9.5</h1>
    <div style="font-family: 'Inter', sans-serif; font-size: 14pt; color: #374151; margin: 0.5em 0;">
      Design and Implementation of a Local-First, Zero-Cloud<br>Vulnerability Intelligence Pipeline
    </div>
  </div>
  <hr style="border-top: 2px solid #e2e8f0; margin: 2em auto; width: 60%;">
  <div style="font-family: 'Inter', sans-serif; margin-top: 2em; color: #374151;">
    <div style="font-size: 13pt; font-weight: 600; margin-bottom: 0.5em;">P R Abinraj</div>
    <div style="font-size: 10pt; color: #6b7280;">
      Repository: github.com/mrQhere/SecurityManagementPlatform<br>
      Version: V9.5.1 &nbsp;|&nbsp; August 2026<br>
      Status: Stable
    </div>
  </div>
</div>
{body_html}
</body>
</html>"""


def generate_pdf():
    """Generate PDF from thesis markdown using WeasyPrint."""
    print("[SMP Thesis PDF Generator]")
    print(f"  Source : {THESIS_MD}")
    print(f"  Output : {THESIS_PDF}")
    print()

    if not os.path.exists(THESIS_MD):
        print(f"  ERROR: Thesis markdown not found at {THESIS_MD}")
        sys.exit(1)

    print("  [1/4] Reading thesis markdown...")
    md_content = read_thesis_md()
    md_content = strip_yaml_frontmatter(md_content)
    print(f"        {len(md_content):,} characters read")

    print("  [2/4] Converting markdown to HTML...")
    body_html = md_to_html(md_content)
    full_html = build_html(body_html)
    print(f"        HTML generated ({len(full_html):,} chars)")

    # Save intermediate HTML for debugging
    html_path = THESIS_PDF.replace(".pdf", ".html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"        HTML saved to {html_path}")

    print("  [3/4] Rendering PDF with WeasyPrint...")
    try:
        # Add venv to path
        venv_site = os.path.join(BASE_DIR, "venv", "lib")
        if os.path.exists(venv_site):
            for entry in os.listdir(venv_site):
                sp = os.path.join(venv_site, entry, "site-packages")
                if os.path.isdir(sp) and sp not in sys.path:
                    sys.path.insert(0, sp)

        from weasyprint import HTML, CSS as WCSS
        from weasyprint.text.fonts import FontConfiguration
        font_config = FontConfiguration()
        html_doc = HTML(string=full_html, base_url=BASE_DIR)
        html_doc.write_pdf(
            THESIS_PDF,
            font_config=font_config,
        )
        size_kb = os.path.getsize(THESIS_PDF) // 1024
        print(f"        PDF rendered successfully ({size_kb} KB)")
    except Exception as e:
        print(f"        WeasyPrint error: {e}")
        print("        Trying alternative method...")
        # Try subprocess approach with weasyprint CLI
        result = subprocess.run(
            [sys.executable, "-m", "weasyprint", html_path, THESIS_PDF],
            capture_output=True, text=True, cwd=BASE_DIR
        )
        if result.returncode == 0:
            size_kb = os.path.getsize(THESIS_PDF) // 1024
            print(f"        PDF rendered via CLI ({size_kb} KB)")
        else:
            print(f"        CLI error: {result.stderr[:200]}")
            sys.exit(1)

    print()
    print("  [4/4] Done!")
    print(f"        Output: {THESIS_PDF}")
    print(f"        Size  : {os.path.getsize(THESIS_PDF) // 1024} KB")


if __name__ == "__main__":
    generate_pdf()
