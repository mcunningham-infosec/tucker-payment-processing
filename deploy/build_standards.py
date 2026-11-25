"""
build_standards.py - turn the standards write-ups (docs/standards/*.md) into website pages and PDFs.

The Markdown files in docs/standards/ are the single source of truth (they are also what GitHub shows). Run this
after editing one:

    python deploy/build_standards.py        (the PDFs need reportlab: pip install reportlab; run locally)

It writes site/standards.html (the list), one site/standard-<name>.html per standard and one
site/standards/<name>.pdf per standard. A test (tests/test_standards_pages.py) fails if the pages are out of date
or if a write-up names a file that doesn't exist, so the evidence can't quietly rot.

The write-ups use a small, fixed subset of Markdown: "# Title", a subtitle line, "## Section", "### Item",
"**Status: ...**", paragraphs, and an "Evidence:" line whose `backticked` repository paths become links to GitHub.
Everything is HTML-escaped first, so a write-up can never inject markup into a page.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import html
import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "standards"
SITE = ROOT / "site"
REPO = "https://github.com/mcunningham-infosec/tucker-payment-processing"

# Display order, page name and a one-line summary (shown on the list pages).
ORDER = [
    ("owasp-llm-top-10", "OWASP Top 10 for LLM Applications 2026", "Each of the ten AI risks, such as prompt injection, sensitive data disclosure and excessive agency, and the control that answers it."),
    ("owasp-agentic-top-10", "OWASP Top 10 for Agentic Applications 2026", "The risks of AI that uses tools and takes actions, from goal hijack to rogue agents, and why both of the site's AI agents have agency without authority."),
    ("mitre-atlas", "MITRE ATLAS", "The attacker techniques that apply to the site's AI, from prompt injection to cost harvesting, and the defense against each."),
    ("nist-ai-rmf", "NIST AI Risk Management Framework", "How Tucker's risks are governed, mapped, measured and managed, across all 19 categories, with NIST's Generative AI Profile."),
    ("iso-42001", "ISO/IEC 42001:2023", "The AI management system behind Tucker: clauses 4 to 10 and the Annex A controls."),
    ("iso-23894", "ISO/IEC 23894:2023", "AI risk management: how the site's AI risks are identified, analyzed, treated and monitored, and the AI-specific risk sources."),
    ("iso-42005", "ISO/IEC 42005:2025", "An AI system impact assessment of Tucker and the AI SOC Squirrel: intended use, misuse, data, benefits, harms and residual risk."),
    ("eu-ai-act", "EU AI Act", "Where Tucker sits in the EU's risk tiers, and the transparency duties that apply."),
    ("pci-dss", "PCI DSS v4.0.1", "All twelve requirements for the store and support chat, starting with the biggest control: keeping card data out."),
    ("soc-2", "SOC 2 Trust Services Criteria", "A readiness review against the criteria a SOC 2 auditor tests, CC1 to CC9 plus the optional categories."),
]
STATUSES = ["Met", "Partly met", "Not applicable"]
CHIP = {"Met": "met", "Partly met": "partly", "Not applicable": "na"}

_spec = importlib.util.spec_from_file_location("build_policy_pages", ROOT / "deploy" / "build_policy_pages.py")
_policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_policy)


def parse(md: str) -> dict:
    """Split a write-up into title, subtitle and sections; each section has intro paragraphs and items."""
    lines = [l.rstrip() for l in md.strip().splitlines()]
    doc = {"title": lines[0].lstrip("# ").strip(), "subtitle": lines[1].strip(), "sections": []}
    section = item = None
    for line in lines[2:]:
        t = line.strip()
        if not t:
            continue
        if t.startswith("## "):
            section, item = {"heading": t[3:].strip(), "paras": [], "items": []}, None
            doc["sections"].append(section)
        elif t.startswith("### "):
            item = {"heading": t[4:].strip(), "status": "", "paras": [], "evidence": ""}
            section["items"].append(item)
        elif t.startswith("**Status:") and item is not None:
            item["status"] = t.strip("*").split(":", 1)[1].strip()
        elif t.startswith("Evidence:"):
            (item if item is not None else section)["evidence"] = t[len("Evidence:"):].strip()
        else:
            (item if item is not None else section)["paras"].append(t)
    return doc


def paths(text: str) -> list:
    """The repository paths named in `backticks`."""
    return [p for p in re.findall(r"`([^`]+)`", text) if "/" in p or p.endswith((".md", ".txt", ".py"))]


def inline(text: str) -> str:
    """Escape, then turn `repo/paths` into GitHub links and **bold** into <strong>."""
    out = html.escape(text, quote=False)

    def link(m):
        p = m.group(1)
        if p in paths(text):
            kind = "tree" if (ROOT / p).is_dir() else "blob"
            return f'<a href="{REPO}/{kind}/main/{p.rstrip("/")}"><code>{p}</code></a>'
        return f"<code>{p}</code>"

    out = re.sub(r"`([^`]+)`", link, out)
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)


def counts(doc: dict) -> dict:
    """How many items have each status."""
    c = {s: 0 for s in STATUSES}
    for sec in doc["sections"]:
        for it in sec["items"]:
            c[it["status"]] = c.get(it["status"], 0) + 1
    return c


def standard_page(name: str, doc: dict) -> str:
    """One write-up as a site page."""
    e = html.escape
    c = counts(doc)
    chips = " ".join(f'<span class="chip {CHIP[s]}">{c[s]} {e(s.lower())}</span>' for s in STATUSES if c[s])
    parts = ['    <section class="card policy standard">\n      <p class="crumb"><a href="standards.html">&larr; All standards</a></p>',
             f"      <h1>{e(doc['title'])}</h1>",
             f'      <p class="muted-line">{e(doc["subtitle"])}</p>',
             f'      <p class="std-summary">{chips} <a class="scan-all" href="standards/{name}.pdf">Download PDF</a></p>']
    for sec in doc["sections"]:
        parts.append(f"      <h2>{e(sec['heading'])}</h2>")
        parts += [f"      <p>{inline(t)}</p>" for t in sec["paras"]]
        if sec.get("evidence"):
            parts.append(f'      <p class="evidence"><strong>Evidence:</strong> {inline(sec["evidence"])}</p>')
        for it in sec["items"]:
            parts.append(f'      <div class="req"><h3>{e(it["heading"])} <span class="chip {CHIP.get(it["status"], "na")}">{e(it["status"])}</span></h3>')
            parts += [f"        <p>{inline(t)}</p>" for t in it["paras"]]
            if it["evidence"]:
                parts.append(f'        <p class="evidence"><strong>Evidence:</strong> {inline(it["evidence"])}</p>')
            parts.append("      </div>")
    parts.append(f'      <p class="muted-line source">This page is generated from <a href="{REPO}/blob/main/docs/standards/{name}.md">'
                 f"docs/standards/{name}.md</a>. Written by Michael Cunningham; a self-assessment, not an audit or certification.</p>\n    </section>")
    return _policy.page(doc["title"], f"{doc['title']}: how Tucker Payment Processing (a fictional company) meets it, with evidence.",
                        "\n".join(parts)).replace("<link rel=\"stylesheet\" href=\"assets/tour.css",
                                                  f"<link rel=\"stylesheet\" href=\"assets/standards.css?v={_policy.VERSION}\">\n  <link rel=\"stylesheet\" href=\"assets/tour.css", 1)


def index_page(docs: list) -> str:
    """The list of standards."""
    e = html.escape
    rows = []
    for name, title, summary, doc in docs:
        c = counts(doc)
        chips = " ".join(f'<span class="chip {CHIP[s]}">{c[s]} {e(s.lower())}</span>' for s in STATUSES if c[s])
        rows.append(f'        <li><a href="standard-{name}.html"><strong>{e(title)}</strong></a> &middot; <a href="standards/{name}.pdf">PDF</a><br>'
                    f'{e(summary)}<br>{chips}</li>')
    body = f"""    <section class="card intro standard">
      <p class="crumb"><a href="policies.html">&larr; AI Policies</a></p>
      <h1>Built to recognized standards</h1>
      <p>For each standard, Michael Cunningham mapped every requirement to what the site actually does, with links to the
        code, configuration or test that proves it. Where the site falls short, or a one-person company can't show what
        a large one would, the write-up says so plainly. These are self-assessments, not audits or certifications.</p>
      <ul class="links policy-list">
{chr(10).join(rows)}
      </ul>
      <p class="muted-line">Each write-up is also in the code repository, in <a href="{REPO}/tree/main/docs/standards">docs/standards</a>.</p>
    </section>"""
    return _policy.page("Standards", "How Tucker Payment Processing (a fictional company) maps to AI, security and payment standards.",
                        body).replace("<link rel=\"stylesheet\" href=\"assets/tour.css",
                                      f"<link rel=\"stylesheet\" href=\"assets/standards.css?v={_policy.VERSION}\">\n  <link rel=\"stylesheet\" href=\"assets/tour.css", 1)


def load() -> list:
    """(name, title, summary, parsed doc) for every standard, in display order."""
    return [(n, t, s, parse((SRC / f"{n}.md").read_text(encoding="utf-8"))) for n, t, s in ORDER]


def build() -> dict:
    """Return {path: html} for every generated page (nothing is written)."""
    docs = load()
    out = {SITE / f"standard-{n}.html": standard_page(n, d) for n, _, _, d in docs}
    out[SITE / "standards.html"] = index_page(docs)
    return out


def pdf(name: str, doc: dict, path: pathlib.Path):
    """One write-up as a PDF, in the same style as the scan reports."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    BLUE, INK, MUTED, LINE = (colors.HexColor(c) for c in ("#1f5fbf", "#1b1f24", "#5b6470", "#d7dce2"))
    COLOR = {"Met": "#1e7d46", "Partly met": "#9a6700", "Not applicable": "#5b6470"}
    S = {k: ParagraphStyle(k, **v) for k, v in {
        "org": dict(fontName="Helvetica-Bold", fontSize=9, textColor=BLUE),
        "title": dict(fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=INK, spaceBefore=2),
        "sub": dict(fontName="Helvetica", fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=4),
        "h2": dict(fontName="Helvetica-Bold", fontSize=12, textColor=BLUE, spaceBefore=12, spaceAfter=4),
        "h3": dict(fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=INK, spaceBefore=8, spaceAfter=2),
        "body": dict(fontName="Helvetica", fontSize=9.3, leading=13.2, textColor=INK, spaceAfter=4),
        "ev": dict(fontName="Helvetica", fontSize=8, leading=11, textColor=MUTED, spaceAfter=2),
        "small": dict(fontName="Helvetica", fontSize=8, leading=11, textColor=MUTED),
    }.items()}

    def rl(text):
        """Our inline Markdown as ReportLab mini-markup (escaped first)."""
        t = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
        return re.sub(r"`([^`]+)`", r'<font name="Courier" size="8">\1</font>', t)

    c = counts(doc)
    summary = " &nbsp; ".join(f'<font color="{COLOR[s]}"><b>{c[s]} {s.lower()}</b></font>' for s in STATUSES if c[s])
    story = [Paragraph("Tucker Payment Processing &middot; Standards self-assessment", S["org"]),
             Paragraph(rl(doc["title"]), S["title"]), Paragraph(rl(doc["subtitle"]), S["sub"]),
             Paragraph(summary, S["body"])]
    for sec in doc["sections"]:
        story.append(Paragraph(rl(sec["heading"]), S["h2"]))
        story += [Paragraph(rl(t), S["body"]) for t in sec["paras"]]
        if sec.get("evidence"):
            story.append(Paragraph("<b>Evidence:</b> " + rl(sec["evidence"]), S["ev"]))
        for it in sec["items"]:
            head = Table([[Paragraph(rl(it["heading"]), S["h3"]),
                           Paragraph(f'<font color="{COLOR.get(it["status"], "#5b6470")}"><b>{rl(it["status"].upper())}</b></font>',
                                     ParagraphStyle("st", parent=S["h3"], alignment=2, fontSize=8.5))]],
                         colWidths=[5.4 * inch, 1.6 * inch])
            head.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, 0), 0.5, LINE), ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
                                      ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
            block = [head, Spacer(1, 3)] + [Paragraph(rl(t), S["body"]) for t in it["paras"]]
            if it["evidence"]:
                block.append(Paragraph("<b>Evidence:</b> " + rl(it["evidence"]), S["ev"]))
            story.append(KeepTogether(block))
    story += [Spacer(1, 10), Paragraph(f"Source: {REPO}/blob/main/docs/standards/{name}.md &middot; Live site: https://tuckerpaymentprocessing.com", S["small"]),
              Paragraph("Written by Michael Cunningham with AI assistance (Claude). A self-assessment, not an audit, certification "
                        "or legal opinion. Tucker Payment Processing is a fictional company and processes no real payments.", S["small"])]

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(0.75 * inch, 0.5 * inch, f"Tucker Payment Processing (fictional company) - {doc['title']} - self-assessment")
        canvas.drawRightString(7.75 * inch, 0.5 * inch, f"Page {d.page}")
        canvas.restoreState()

    path.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(str(path), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.7 * inch,
                      bottomMargin=0.8 * inch, title=doc["title"], author="Michael Cunningham", invariant=1,
                      subject="Tucker Payment Processing standards self-assessment").build(story, onFirstPage=footer, onLaterPages=footer)


if __name__ == "__main__":
    for p, text in build().items():
        p.write_text(text, encoding="utf-8")
        print("wrote", p.relative_to(ROOT))
    if "--no-pdf" not in sys.argv:
        for n, _, _, d in load():
            pdf(n, d, SITE / "standards" / f"{n}.pdf")
            print("wrote", f"site/standards/{n}.pdf")
