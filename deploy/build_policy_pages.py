"""
build_policy_pages.py - turn the company policies (policies/*.md) into pages on the website.

The Markdown files in policies/ are the single source of truth: Tucker answers from them, and these pages show
visitors exactly the same text. Run this after editing a policy:

    python deploy/build_policy_pages.py

It writes site/policies.html (the list), one site/policy-<name>.html per policy and a PDF of each
(site/policies/<name>.pdf; skip with --no-pdf). A test
(tests/test_policy_pages.py) fails if the pages are out of date, so the website can't drift from what Tucker reads.

The policies use a small, fixed subset of Markdown: "# Title", a subtitle line, "## Section" headings and
paragraphs. Everything is HTML-escaped, so policy text can never inject markup into a page.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import html
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICIES = ROOT / "policies"
SITE = ROOT / "site"
VERSION = "20261127c"          # same asset version as the other pages (see apache-hardening.conf)
COPYRIGHT = "\u00a9 2026 Michael Cunningham, Root Cause Associates. All rights reserved."   # on every page of every PDF, and in its metadata
GITHUB = "https://github.com/mcunningham-infosec/tucker-payment-processing/blob/main/policies/"

# Display order, page name and a one-line summary for the policy list.
ORDER = [
    ("ai-assistant-policy", "policy-ai-assistant", "What Tucker, our AI assistant, may and may not do, and the guardrails around him."),
    ("card-security-and-privacy", "policy-card-security", "How card data is protected, and what support will never ask you for."),
    ("refunds-and-disputes", "policy-refunds-disputes", "Refunds, disputes and declined transactions."),
    ("data-retention", "policy-data-retention", "What the site keeps, for how long and the cookies it uses."),
]


def parse(md: str) -> dict:
    """Split a policy into its title, subtitle and (heading, [paragraphs]) sections."""
    lines = [l.rstrip() for l in md.strip().splitlines()]
    title = lines[0].lstrip("# ").strip()
    subtitle = lines[1].strip() if len(lines) > 1 and not lines[1].startswith("#") else ""
    sections, current = [], None
    for line in lines[2 if subtitle else 1:]:
        if line.startswith("## "):
            current = (line[3:].strip(), [])
            sections.append(current)
        elif line.strip() and current is not None:
            current[1].append(line.strip())
    return {"title": title, "subtitle": subtitle, "sections": sections}


def _seo(path: str, title: str, description: str) -> str:
    """Canonical URL and link-preview tags, so search engines index the production address only."""
    if not path:
        return ""
    url, t, d = f"https://tuckerpaymentprocessing.com/{path}", html.escape(f"{title} - Tucker Payment Processing"), html.escape(description)
    return (f'  <link rel="canonical" href="{url}">\n  <meta property="og:type" content="website">\n'
            f'  <meta property="og:site_name" content="Tucker Payment Processing">\n  <meta property="og:title" content="{t}">\n'
            f'  <meta property="og:description" content="{d}">\n  <meta property="og:url" content="{url}">\n')


_EXT_LINK = re.compile(r'<a\b([^>]*?)\bhref="(https?://[^"]+)"([^>]*)>')


def external_links(text: str) -> str:
    """Links to other sites (GitHub, Root Cause Associates, LinkedIn...) open in a new tab."""
    def fix(m):
        pre, url, post = m.groups()
        if "tuckerpaymentprocessing.com" in url or "target=" in pre + post:
            return m.group(0)
        return f'<a{pre}href="{url}"{post} target="_blank" rel="noopener noreferrer">'
    return _EXT_LINK.sub(fix, text)


def page(title: str, description: str, body: str, path: str = "") -> str:
    """A full site page with links to other sites opening in a new tab."""
    return external_links(_page_frame(title, description, body, path))


def _page_frame(title: str, description: str, body: str, path: str = "") -> str:
    """A full site page: the standard header and tabs (AI Policies highlighted), the body, footer and tour."""
    e = html.escape
    return f"""<!doctype html>
<!--
  {e(title)} - generated from the policies folder by deploy/build_policy_pages.py. Edit the policy, not this file.
  Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
-->
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="favicon.ico" sizes="any">
  <link rel="icon" type="image/png" href="assets/favicon-32.png">
  <link rel="apple-touch-icon" href="assets/apple-touch-icon.png">
  <title>{e(title)} - Tucker Payment Processing</title>
  <meta name="description" content="{e(description)}">
{_seo(path, title, description)}  <link rel="stylesheet" href="assets/site.css?v={VERSION}">
  <link rel="stylesheet" href="assets/chat.css?v={VERSION}">
  <link rel="stylesheet" href="assets/about.css?v={VERSION}">
  <link rel="stylesheet" href="assets/tour.css?v={VERSION}">
</head>
<body class="home-page">
  <header class="top">
    <a class="home" href="./"><span class="logo">Tucker <span>Payment</span> Processing</span></a>
    <div class="tag">An AI Governance, Technology and Security Demonstration</div>
    <nav class="tabs" aria-label="Site">
      <a href="./">Home</a>
      <a href="treats.html">Tucker's Treats</a>
      <a href="cipher.html">Cipher's Lair</a>
      <a href="about.html">About Us</a>
      <a href="policies.html" aria-current="page">AI Policies</a>
      <a href="standards.html">Standards</a>
      <a href="https://github.com/mcunningham-infosec/tucker-payment-processing">GitHub</a>
    </nav>
  </header>

  <main class="about-page">
{body}
  </main>

  <footer>Tucker Payment Processing is a fictional company created as a technology demonstration. It does not process real payments. All data is fictional. <span class="copyright">&copy; 2026 Michael Cunningham, <a href="https://rootcauseassociates.com">Root Cause Associates</a>. All rights reserved. <a href="https://github.com/mcunningham-infosec/tucker-payment-processing/blob/main/LICENSE">License</a></span></footer>
  <script src="assets/tour.js?v={VERSION}" defer></script>
</body>
</html>
"""


def policy_page(src: str, p: dict, path: str = "") -> str:
    """One policy as a site page: title, policy id, each section, and a note that it's generated from the .md."""
    e = html.escape
    parts = ['    <section class="card policy">\n      <p class="crumb"><a href="policies.html">&larr; All policies</a></p>',
             f"      <h1>{e(p['title'])}</h1>"]
    if p["subtitle"]:
        parts.append(f'      <p class="muted-line">{e(p["subtitle"])}</p>')
    parts.append(f'      <p><a class="scan-all" href="policies/{src}.pdf">Download PDF</a></p>')
    for heading, paras in p["sections"]:
        parts.append(f"      <h2>{e(heading)}</h2>")
        parts.extend(f"      <p>{e(t)}</p>" for t in paras)
    parts.append(f'      <p class="muted-line source">This page is generated from <a href="{GITHUB}{src}.md">{src}.md</a>, '
                 "the same document Tucker answers from.</p>\n    </section>")
    return page(p["title"], f"{p['title']} of Tucker Payment Processing (a fictional company).", "\n".join(parts), path)


def index_page(items) -> str:
    """The AI Policies page: the list of policies, each with its PDF."""
    e = html.escape
    rows = "\n".join(f'        <li><a href="{name}.html"><strong>{e(p["title"])}</strong></a> &middot; '
                     f'<a href="policies/{src}.pdf">PDF</a><br>{e(summary)}</li>'
                     for src, name, p, summary in items)
    body = f"""    <section class="card intro">
      <h1>AI Policies</h1>
      <p>Michael wrote the company's policies first, then built the AI to follow them. Tucker answers policy questions
        from these exact documents and names his source, and the guardrails in the code enforce what they promise.</p>
      <ul class="links policy-list">
{rows}
      </ul>
    </section>"""
    return page("AI Policies", "The AI and company policies of Tucker Payment Processing (a fictional company).", body, "policies.html")


def pdf(src: str, p: dict, path: pathlib.Path):
    """One policy as a PDF, in the same style as the standards write-ups and scan reports."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    BLUE, INK, MUTED = (colors.HexColor(c) for c in ("#1f5fbf", "#1b1f24", "#5b6470"))
    S = {k: ParagraphStyle(k, **v) for k, v in {
        "org": dict(fontName="Helvetica-Bold", fontSize=9, textColor=BLUE),
        "title": dict(fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=INK, spaceBefore=2),
        "sub": dict(fontName="Helvetica", fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=4),
        "h2": dict(fontName="Helvetica-Bold", fontSize=12, textColor=BLUE, spaceBefore=12, spaceAfter=4, keepWithNext=1),
        "body": dict(fontName="Helvetica", fontSize=9.3, leading=13.2, textColor=INK, spaceAfter=4),
        "small": dict(fontName="Helvetica", fontSize=8, leading=11, textColor=MUTED),
    }.items()}
    esc = html.escape
    story = [Paragraph("Tucker Payment Processing &middot; Company policy", S["org"]),
             Paragraph(esc(p["title"]), S["title"])]
    if p["subtitle"]:
        story.append(Paragraph(esc(p["subtitle"]), S["sub"]))
    for heading, paras in p["sections"]:
        story.append(Paragraph(esc(heading), S["h2"]))
        story += [Paragraph(esc(t), S["body"]) for t in paras]
    story += [Spacer(1, 10), Paragraph(f"Source: {GITHUB}{src}.md (the same document Tucker answers from) &middot; "
                                       "Live site: https://tuckerpaymentprocessing.com", S["small"]),
              Paragraph("Tucker Payment Processing is a fictional company created as a technology demonstration and "
                        "processes no real payments.", S["small"])]

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(0.75 * inch, 0.5 * inch, f"Tucker Payment Processing (fictional company) - {p['title']}")
        canvas.drawRightString(7.75 * inch, 0.5 * inch, f"Page {d.page}")
        canvas.drawCentredString(4.25 * inch, 0.33 * inch, COPYRIGHT)
        canvas.restoreState()

    path.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(str(path), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.7 * inch,
                      bottomMargin=0.8 * inch, title=p["title"], author="Michael Cunningham", invariant=1,
                      subject="Tucker Payment Processing company policy", keywords=COPYRIGHT).build(story, onFirstPage=footer, onLaterPages=footer)


def build() -> dict:
    """Return {path: html} for every generated page (nothing is written)."""
    out, items = {}, []
    for src, name, summary in ORDER:
        p = parse((POLICIES / f"{src}.md").read_text(encoding="utf-8"))
        out[SITE / f"{name}.html"] = policy_page(src, p, f"{name}.html")
        items.append((src, name, p, summary))
    out[SITE / "policies.html"] = index_page(items)
    return out


if __name__ == "__main__":
    for path, text in build().items():
        path.write_text(text, encoding="utf-8")
        print("wrote", path.relative_to(ROOT))
    if "--no-pdf" not in sys.argv:
        for src, _name, _summary in ORDER:
            pdf(src, parse((POLICIES / f"{src}.md").read_text(encoding="utf-8")), SITE / "policies" / f"{src}.pdf")
            print("wrote", f"site/policies/{src}.pdf")
