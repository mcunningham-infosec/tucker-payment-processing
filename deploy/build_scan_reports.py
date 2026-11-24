"""
build_scan_reports.py - turn the independent security-scan results into downloadable PDF reports.

Input:  docs/scans/<date>/results.json   (the results, recorded from each scanner's result page)
Output: site/scans/<date>/<scanner>.pdf  (one report per scanner)
        site/scans/<date>/summary.pdf    (all scanners on one page)

    python deploy/build_scan_reports.py 2026-11-24     (needs reportlab: pip install reportlab; run locally, not on the server)

Each report shows the scanner, the exact scan times (UTC), the grade before and after any fixes, every check, what
was fixed, and a link to run the same scan yourself, so a reader never has to take the PDF's word for it.
"""
import json
import pathlib
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = pathlib.Path(__file__).resolve().parent.parent
BLUE, ORANGE, INK, MUTED = colors.HexColor("#1f5fbf"), colors.HexColor("#ff8a1f"), colors.HexColor("#1b1f24"), colors.HexColor("#5b6470")
OK, BAD, WARN, LINE = colors.HexColor("#1e7d46"), colors.HexColor("#b3261e"), colors.HexColor("#9a6700"), colors.HexColor("#d7dce2")

S = {
    "org": ParagraphStyle("org", fontName="Helvetica-Bold", fontSize=9, textColor=BLUE),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=INK, spaceBefore=2),
    "sub": ParagraphStyle("sub", fontName="Helvetica", fontSize=9.5, leading=13, textColor=MUTED),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11, textColor=BLUE, spaceBefore=12, spaceAfter=4),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=11, textColor=MUTED),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.5, leading=11, textColor=INK),
    "grade": ParagraphStyle("grade", fontName="Helvetica-Bold", fontSize=24, leading=28, alignment=1),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=INK),
}
LABEL = {"recommendation": "ADVISED"}       # short labels so the status columns stay narrow
STATUS_COLOR = {"pass": OK, "fixed": OK, "fail": BAD, "info": MUTED, "recommendation": WARN, "limit": WARN}


def hx(c):
    return "#" + c.hexval()[2:]


def esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def grade_box(label, grade, when, color):
    t = Table([[Paragraph(f'<font size="8" color="#5b6470">{esc(label)}</font>', S["cell"])],
               [Paragraph(f'<font name="Helvetica-Bold" size="24" color="{hx(color)}">{esc(grade)}</font>', S["grade"])],
               [Paragraph(f'<font size="7.5" color="#5b6470">{esc(when)}</font>', S["cell"])]],
              colWidths=[1.7 * inch], rowHeights=[16, 36, 16])
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 1, LINE), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, -1), colors.white)]))
    return t


def checks_table(rows):
    body = [[Paragraph("<b>Check</b>", S["cell"]), Paragraph("<b>Before</b>", S["cell"]), Paragraph("<b>After</b>", S["cell"]),
             Paragraph("<b>Detail</b>", S["cell"])]]
    style = [("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f5f8")), ("TOPPADDING", (0, 0), (-1, -1), 3),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i, r in enumerate(rows, start=1):
        b, a = r.get("before", ""), r.get("after", "")
        body.append([Paragraph(esc(r["check"]), S["cellb"]),
                     Paragraph(f'<font color="{hx(STATUS_COLOR.get(b.lower(), INK))}"><b>{esc(LABEL.get(b.lower(), b.upper()))}</b></font>', S["cell"]),
                     Paragraph(f'<font color="{hx(STATUS_COLOR.get(a.lower(), INK))}"><b>{esc(LABEL.get(a.lower(), a.upper()))}</b></font>', S["cell"]),
                     Paragraph(esc(r.get("detail", "")), S["cell"])])
    t = Table(body, colWidths=[1.9 * inch, 0.8 * inch, 0.8 * inch, 3.5 * inch], repeatRows=1)
    t.setStyle(TableStyle(style))
    return t


def footer(canvas, doc, line):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.75 * inch, 0.5 * inch, line)
    canvas.drawRightString(7.75 * inch, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


def header(story, title, subtitle):
    story.append(Paragraph("Tucker Payment Processing - Independent Security Scan", S["org"]))
    story.append(Paragraph(esc(title), S["title"]))
    story.append(Paragraph(subtitle, S["sub"]))
    story.append(Spacer(1, 4))
    rule = Table([[""]], colWidths=[7 * inch], rowHeights=[3])
    rule.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, -1), 2, BLUE)]))
    story.append(rule)


def scanner_pdf(data, scan, out):
    story = []
    header(story, scan["name"], f'Site tested: <b>{esc(data["site"])}</b> &nbsp;|&nbsp; Scan date: <b>{esc(data["date"])}</b> '
                                f'&nbsp;|&nbsp; Scanner: {esc(scan["scanner"])}')
    story.append(Spacer(1, 10))
    boxes = [grade_box("BEFORE FIXES", scan["before"]["grade"], scan["before"]["time"], BAD if scan["before"].get("bad") else OK),
             grade_box("FINAL", scan["after"]["grade"], scan["after"]["time"], OK)]
    gt = Table([boxes + [Paragraph(esc(scan["summary"]), S["body"])]], colWidths=[1.85 * inch, 1.85 * inch, 3.3 * inch])
    gt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(gt)
    if scan.get("fixes"):
        story.append(Paragraph("What was found and fixed", S["h2"]))
        for f in scan["fixes"]:
            story.append(Paragraph("&bull; " + esc(f), S["body"]))
    story.append(Paragraph("Checks", S["h2"]))
    story.append(checks_table(scan["checks"]))
    if scan.get("notes"):
        story.append(Paragraph("Notes", S["h2"]))
        for n in scan["notes"]:
            story.append(Paragraph("&bull; " + esc(n), S["body"]))
    story.append(Paragraph("Verify it yourself", S["h2"]))
    story.append(Paragraph(f'Run the same scan live: <link href="{esc(scan["retest"])}" color="#1f5fbf">{esc(scan["retest"])}</link>', S["body"]))
    if scan.get("permalink"):
        story.append(Paragraph(f'Scanner\'s saved result: <link href="{esc(scan["permalink"])}" color="#1f5fbf">{esc(scan["permalink"])}</link>', S["body"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(esc(data["method"]), S["small"]))
    doc = SimpleDocTemplate(str(out), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.7 * inch,
                            bottomMargin=0.8 * inch, title=f'{scan["name"]} - {data["site"]} - {data["date"]}',
                            author="Michael Cunningham", subject="Independent security scan results", creator="tuckerpaymentprocessing.com")
    line = f'Tucker Payment Processing (fictional company) - {scan["name"]} - {data["date"]}'
    doc.build(story, onFirstPage=lambda c, d: footer(c, d, line), onLaterPages=lambda c, d: footer(c, d, line))


def summary_pdf(data, out):
    story = []
    header(story, "Security Scan Summary", f'Site tested: <b>{esc(data["site"])}</b> &nbsp;|&nbsp; Scan date: <b>{esc(data["date"])}</b>')
    story.append(Spacer(1, 8))
    story.append(Paragraph(esc(data["intro"]), S["body"]))
    story.append(Spacer(1, 8))
    body = [[Paragraph(f"<b>{h}</b>", S["cell"]) for h in ("Scanner", "What it checks", "Before", "Final")]]
    for sc in data["scans"]:
        body.append([Paragraph(f'<b>{esc(sc["name"])}</b>', S["cell"]), Paragraph(esc(sc["checks_what"]), S["cell"]),
                     Paragraph(f'<font color="#b3261e"><b>{esc(sc["before"]["grade"])}</b></font>' if sc["before"].get("bad")
                               else f'<b>{esc(sc["before"]["grade"])}</b>', S["cell"]),
                     Paragraph(f'<font color="#1e7d46"><b>{esc(sc["after"]["grade"])}</b></font>', S["cell"])])
    t = Table(body, colWidths=[1.7 * inch, 3.5 * inch, 0.9 * inch, 0.9 * inch], repeatRows=1)
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f5f8")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    story.append(Paragraph("Fixes made on " + esc(data["date"]), S["h2"]))
    for f in data["fixes_made"]:
        story.append(Paragraph("&bull; " + esc(f), S["body"]))
    if data.get("known_limits"):
        story.append(Paragraph("Known limits", S["h2"]))
        for f in data["known_limits"]:
            story.append(Paragraph("&bull; " + esc(f), S["body"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(esc(data["method"]), S["small"]))
    doc = SimpleDocTemplate(str(out), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.7 * inch,
                            bottomMargin=0.8 * inch, title=f'Security Scan Summary - {data["site"]} - {data["date"]}',
                            author="Michael Cunningham", subject="Independent security scan results", creator="tuckerpaymentprocessing.com")
    line = f'Tucker Payment Processing (fictional company) - Security Scan Summary - {data["date"]}'
    doc.build(story, onFirstPage=lambda c, d: footer(c, d, line), onLaterPages=lambda c, d: footer(c, d, line))


def main(date):
    data = json.loads((ROOT / "docs" / "scans" / date / "results.json").read_text(encoding="utf-8"))
    out = ROOT / "site" / "scans" / date
    out.mkdir(parents=True, exist_ok=True)
    for sc in data["scans"]:
        scanner_pdf(data, sc, out / f'{sc["id"]}.pdf')
        print("wrote", (out / f'{sc["id"]}.pdf').relative_to(ROOT))
    summary_pdf(data, out / "summary.pdf")
    print("wrote", (out / "summary.pdf").relative_to(ROOT))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "2026-11-24")
