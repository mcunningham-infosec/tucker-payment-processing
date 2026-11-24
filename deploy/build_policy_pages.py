"""
build_policy_pages.py - turn the company policies (policies/*.md) into pages on the website.

The Markdown files in policies/ are the single source of truth: Tucker answers from them, and these pages show
visitors exactly the same text. Run this after editing a policy:

    python deploy/build_policy_pages.py

It writes site/policies.html (the list) and one site/policy-<name>.html per policy. A test
(tests/test_policy_pages.py) fails if the pages are out of date, so the website can't drift from what Tucker reads.

The policies use a small, fixed subset of Markdown: "# Title", a subtitle line, "## Section" headings and
paragraphs. Everything is HTML-escaped, so policy text can never inject markup into a page.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import html
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICIES = ROOT / "policies"
SITE = ROOT / "site"
VERSION = "20261124i"          # same asset version as the other pages (see apache-hardening.conf)
GITHUB = "https://github.com/mcunningham-infosec/tucker-payment-processing/blob/main/policies/"

# Display order, page name and a one-line summary for the policy list.
ORDER = [
    ("ai-assistant-policy", "policy-ai-assistant", "What Tucker, our AI assistant, may and may not do, and the guardrails around him."),
    ("card-security-and-privacy", "policy-card-security", "How card data is protected, and what support will never ask you for."),
    ("refunds-and-disputes", "policy-refunds-disputes", "Refunds, disputes and declined transactions."),
    ("data-retention", "policy-data-retention", "What the site keeps, for how long, and the cookies it uses."),
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


def page(title: str, description: str, body: str) -> str:
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
  <title>{e(title)} - Tucker Payment Processing</title>
  <meta name="description" content="{e(description)}">
  <link rel="stylesheet" href="assets/site.css?v={VERSION}">
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
      <a href="https://github.com/mcunningham-infosec/tucker-payment-processing">Code on GitHub</a>
    </nav>
  </header>

  <main class="about-page">
{body}
  </main>

  <footer>Tucker Payment Processing is a fictional company created as a technology demonstration. It does not process real payments. All data is fictional. <span class="copyright">&copy; 2026 Michael Cunningham. All rights reserved. <a href="https://github.com/mcunningham-infosec/tucker-payment-processing/blob/main/LICENSE">License</a></span></footer>
  <script src="assets/tour.js?v={VERSION}" defer></script>
</body>
</html>
"""


def policy_page(src: str, p: dict) -> str:
    """One policy as a site page: title, policy id, each section, and a note that it's generated from the .md."""
    e = html.escape
    parts = ['    <section class="card policy">\n      <p class="crumb"><a href="policies.html">&larr; All policies</a></p>',
             f"      <h1>{e(p['title'])}</h1>"]
    if p["subtitle"]:
        parts.append(f'      <p class="muted-line">{e(p["subtitle"])}</p>')
    for heading, paras in p["sections"]:
        parts.append(f"      <h2>{e(heading)}</h2>")
        parts.extend(f"      <p>{e(t)}</p>" for t in paras)
    parts.append(f'      <p class="muted-line source">This page is generated from <a href="{GITHUB}{src}.md">{src}.md</a>, '
                 "the same document Tucker answers from.</p>\n    </section>")
    return page(p["title"], f"{p['title']} of Tucker Payment Processing (a fictional company).", "\n".join(parts))


def index_page(items) -> str:
    """The AI Policies page: the list of policies and the standards the site is built to."""
    e = html.escape
    rows = "\n".join(f'        <li><a href="{name}.html"><strong>{e(p["title"])}</strong></a><br>{e(summary)}</li>'
                     for name, p, summary in items)
    body = f"""    <section class="card intro">
      <h1>AI Policies</h1>
      <p>Michael wrote the company's policies first, then built the AI to follow them. Tucker answers policy questions
        from these exact documents and names his source, and the guardrails in the code enforce what they promise.</p>
      <ul class="links policy-list">
{rows}
      </ul>
    </section>

    <section class="card">
      <h2>Built to recognized standards</h2>
      <ul>
        <li><strong>PCI DSS v4.0:</strong> no card data ever entered or exposed, tokens and last 4 digits only, server-side pricing, least-privilege database roles, strong HTTPS and logging.</li>
        <li><strong>NIST AI Risk Management Framework (AI RMF 1.0):</strong> how Tucker's risks are governed, mapped, measured and managed, including NIST's Generative AI Profile.</li>
        <li><strong>ISO/IEC 42001:2023:</strong> the AI management system behind Tucker: policy, roles, risk assessment, controls and review.</li>
        <li><strong>OWASP Top 10 for LLM Applications (2025):</strong> each LLM risk, such as prompt injection, sensitive data disclosure and excessive agency, and the guardrail that answers it.</li>
        <li><strong>EU AI Act (transparency):</strong> Tucker always discloses that he is an AI.</li>
      </ul>
      <p class="muted-line">A write-up for each standard, requirement by requirement, is coming soon.</p>
    </section>"""
    return page("AI Policies", "The AI and company policies of Tucker Payment Processing (a fictional company).", body)


def build() -> dict:
    """Return {path: html} for every generated page (nothing is written)."""
    out, items = {}, []
    for src, name, summary in ORDER:
        p = parse((POLICIES / f"{src}.md").read_text(encoding="utf-8"))
        out[SITE / f"{name}.html"] = policy_page(src, p)
        items.append((name, p, summary))
    out[SITE / "policies.html"] = index_page(items)
    return out


if __name__ == "__main__":
    for path, text in build().items():
        path.write_text(text, encoding="utf-8")
        print("wrote", path.relative_to(ROOT))
