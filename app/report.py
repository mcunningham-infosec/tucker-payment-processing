"""
report.py - the site owner's daily security & activity summary, emailed every night at 11:50 PM Eastern
(just before the midnight reset wipes the day's demo data), plus short real-time warnings.

    /opt/tucker-venv/bin/python -m app.report            # build today's report and email it
    /opt/tucker-venv/bin/python -m app.report --print    # build it and print it instead (testing)

What goes in:
  - Visitors: from the web server's log (real visitor IPs come from Cloudflare's header, see
    deploy/apache-cloudflare.conf). For each address: rough location (from Cloudflare), the network's owner
    (reverse DNS and the public ASN registry), pages viewed, and whether it looks like a person or a bot.
  - Activity: chat questions, identity checks, store orders, Cipher runs and guardrail events, from the app's
    own event table (which holds no chat text and no IP addresses).
  - Spend: today's and this month's AI cost against the caps.
  - Anything unusual: errors, scanners, one address making an outsized share of requests, guardrail hits,
    lockouts, alerts, a Cipher attack that got through, spend climbing.

Privacy: web server logs are kept for at most two days (deploy/logrotate-apache2) and this email is the only
summary of them. Email goes out through Resend (RESEND_API_KEY in /etc/tucker/tucker.env, never in this repo).
Everything taken from requests (paths, user agents) is attacker-controlled, so it is HTML-escaped and shortened.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import collections
import datetime as dt
import html
import json
import os
import re
import socket
import sys
import urllib.request
from zoneinfo import ZoneInfo

from . import db
from .config import SETTINGS

ET = ZoneInfo("America/New_York")
LOGS = [p for p in os.environ.get("REPORT_ACCESS_LOGS", "/var/log/apache2/access.log.1,/var/log/apache2/access.log").split(",") if p]
LOCAL = {"127.0.0.1", "::1"}                           # Cipher's own attack traffic: reported separately

# Apache "combined" format plus the Cloudflare location fields we append (deploy/apache-cloudflare.conf).
LINE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<t>[^\]]+)\] "(?P<m>[A-Z]+) (?P<path>\S+)[^"]*" (?P<st>\d{3}) \S+ '
                  r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"(?: cf="(?P<cc>[^|"]*)\|(?P<reg>[^|"]*)\|(?P<city>[^"]*)")?')
PAGE = re.compile(r"^/(?:$|[\w-]+\.html$)")             # real page views (not images, scripts or API calls)
BOT_UA = re.compile(r"bot|crawl|spider|slurp|curl|wget|python|scan|httpx|go-http|zgrab|masscan|nmap|headless|preview", re.I)
SCAN_PATH = re.compile(r"\.(php|asp|aspx|jsp|cgi|env|git|bak|sql|ini|yml)\b|wp-|/admin|/\.(?!well-known)", re.I)


def _day_bounds(day: dt.date):
    """Midnight to midnight, Eastern time, for the given day."""
    start = dt.datetime.combine(day, dt.time(0), ET)
    return start, start + dt.timedelta(days=1)


def read_log(day: dt.date, paths=None):
    """Every web request for this (Eastern) day, except Cipher's own loopback traffic."""
    out = []
    for p in paths or LOGS:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                for raw in f:
                    m = LINE.match(raw)
                    if not m or m["ip"] in LOCAL:
                        continue
                    try:
                        when = dt.datetime.strptime(m["t"], "%d/%b/%Y:%H:%M:%S %z").astimezone(ET)
                    except ValueError:
                        continue
                    if when.date() == day:
                        out.append({**m.groupdict(), "when": when, "status": int(m["st"])})
        except OSError:
            continue
    return out


def network_owner(ip: str) -> str:
    """Who runs this address: the ASN registry name (e.g. 'COMCAST-7922') and the reverse-DNS domain.
    Uses public DNS only (Team Cymru's free IP-to-ASN service), for IPv4 and IPv6 (phone carriers such as
    T-Mobile give visitors IPv6 addresses). Best effort: a failed lookup just leaves that part out."""
    import ipaddress
    parts = []
    try:
        import dns.resolver                                 # dnspython
        r = dns.resolver.Resolver()
        r.lifetime = 3
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        else:                                               # IPv6: reversed hex nibbles, Cymru's origin6 zone
            q = ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
        asn = str(r.resolve(q, "TXT")[0]).strip('"').split("|")[0].strip().split()[0]
        name = str(r.resolve(f"AS{asn}.asn.cymru.com", "TXT")[0]).strip('"').split("|")[-1].strip()
        parts.append(f"{name} (AS{asn})")
    except Exception:       # noqa: S110 - best effort: no answer just means "owner unknown"
        pass
    try:
        socket.setdefaulttimeout(3)
        host = socket.gethostbyaddr(ip)[0]
        parts.append(".".join(host.split(".")[-3:]))
    except Exception:       # noqa: S110 - many addresses have no reverse DNS name
        pass
    return " / ".join(parts) or "unknown"


def visitors(entries, lookup=network_owner):
    """Group the day's requests by address."""
    by = collections.OrderedDict()
    for e in sorted(entries, key=lambda e: e["when"]):
        v = by.setdefault(e["ip"], {"ip": e["ip"], "first": e["when"], "last": e["when"], "requests": 0,
                                    "pages": collections.Counter(), "scans": collections.Counter(), "errors": 0, "assets": 0,
                                    "ua": e["ua"], "where": ", ".join(x for x in (e["city"], e["reg"], e["cc"]) if x)})
        v["last"] = e["when"]
        v["requests"] += 1
        if PAGE.match(e["path"]) and e["status"] < 400:
            v["pages"][e["path"]] += 1
        if e["path"].startswith("/assets/") and e["path"].endswith((".css", ".js")) and e["status"] < 400:
            v["assets"] += 1
        if SCAN_PATH.search(e["path"]):
            v["scans"][e["path"][:80]] += 1
        if e["status"] >= 500:
            v["errors"] += 1
    for v in by.values():
        # A person views a page AND their browser loads its styles/scripts; scanners with a browser-like name rarely do.
        v["bot"] = bool(BOT_UA.search(v["ua"])) or not v["pages"] or not v["assets"]
        v["scanner"] = sum(v["scans"].values()) >= 3
    people = [v for v in by.values() if not v["bot"]]
    for v in people[:40]:                                   # look up owners for people (bounded: DNS is slow)
        v["owner"] = lookup(v["ip"])
    return list(by.values())


def app_activity(day: dt.date):
    """Counts from the app's own event table, orders, Cipher runs and AI spend."""
    start, end = _day_bounds(day)
    with db.connect() as c:
        # Cipher's own demo traffic is tagged "cipher-..." (db.event_session) and counted separately.
        ev = {r["event_type"]: r["n"] for r in c.execute(
            "SELECT event_type, count(*) AS n FROM ops.chat_events WHERE at >= %s AND at < %s "
            "AND session_id NOT LIKE 'cipher-%%' GROUP BY 1", (start, end)).fetchall()}
        cipher_events = c.execute("SELECT count(*) AS n FROM ops.chat_events WHERE session_id LIKE 'cipher-%%' "
                                  "AND at >= %s AND at < %s", (start, end)).fetchone()["n"]
        sessions = c.execute("SELECT count(DISTINCT session_id) AS n FROM ops.chat_events WHERE event_type = 'message' "
                             "AND session_id NOT LIKE 'cipher-%%' AND at >= %s AND at < %s", (start, end)).fetchone()["n"]
        details = c.execute("SELECT event_type, detail FROM ops.chat_events WHERE event_type IN ('alert','cipher_run') "
                            "AND at >= %s AND at < %s ORDER BY at", (start, end)).fetchall()
        orders = c.execute("SELECT count(*) AS n, coalesce(sum(total),0) AS total FROM demo.orders "
                           "WHERE source = 'web' AND created_at >= %s AND created_at < %s",
                           (start.replace(tzinfo=None), end.replace(tzinfo=None))).fetchone()
    return {"events": ev, "chat_sessions": sessions, "cipher_events": cipher_events, "orders": orders["n"], "orders_total": float(orders["total"]),
            "alerts": [d["detail"] for d in details if d["event_type"] == "alert"],
            "cipher_runs": [d["detail"] for d in details if d["event_type"] == "cipher_run"],
            "spend_day": db.ai_spend_since("day"), "spend_month": db.ai_spend_since("month")}


def unusual(vis, act):
    """Plain-English list of anything worth a look."""
    notes = []
    total = sum(v["requests"] for v in vis) or 1
    for v in vis:
        if v["requests"] >= 300 and v["requests"] / total >= 0.4:
            notes.append(f"{v['ip']} made {v['requests']} of {total} requests ({v['requests'] * 100 // total}%).")
        if v["errors"]:
            notes.append(f"{v['ip']} triggered {v['errors']} server error(s) (5xx): worth checking.")
    scanners = [v for v in vis if v["scanner"]]
    if scanners:
        paths = collections.Counter()
        for v in scanners:
            paths.update(v["scans"])
        notes.append(f"{len(scanners)} address(es) probed for common weak spots (top: "
                     f"{', '.join(p for p, _ in paths.most_common(3))}). Routine internet noise; all refused.")
    ev = act["events"]
    labels = {"injection_blocked": "prompt-injection attempt(s) blocked", "masked_output": "reply(ies) masked by the output filter",
              "order_tamper_refused": "tampered order(s) refused", "model_error": "AI model error(s)",
              "rate_limited": "chat rate-limit hit(s)", "fair_share": "network(s) hit the daily AI fair share",
              "nap": "time(s) the AI budget cap made Tucker nap", "verify_fail": "failed identity check(s)"}
    for k, label in labels.items():
        if ev.get(k):
            notes.append(f"{ev[k]} {label}.")
    for a in act["alerts"]:
        notes.append(f"Alert: {a}")
    for r in act["cipher_runs"]:
        if "GOT THROUGH" in r:
            notes.append(f"Cipher run: {r}")
    if act["spend_day"] >= SETTINGS.daily_cap_usd * 0.5:
        notes.append(f"AI spend today is ${act['spend_day']:.2f}, over half the ${SETTINGS.daily_cap_usd:.2f} daily cap.")
    return notes


def build(day: dt.date, entries=None, activity=None, lookup=network_owner):
    """Assemble the report. Returns (subject, plain_text, html)."""
    vis = visitors(read_log(day) if entries is None else entries, lookup)
    act = app_activity(day) if activity is None else activity
    people = [v for v in vis if not v["bot"]]
    bots = [v for v in vis if v["bot"]]
    notes = unusual(vis, act)
    e = act["events"]
    views = sum(sum(v["pages"].values()) for v in people)
    subject = (f"Tucker daily report {day:%a %b %d}: {len(people)} visitor{'s' if len(people) != 1 else ''}, "
               f"{views} page view{'s' if views != 1 else ''}, "
               f"{e.get('message', 0)} chats, ${act['spend_day']:.2f} AI" + (f", {len(notes)} to review" if notes else ""))

    def esc(x, n=120):
        """HTML-escape and shorten: paths and user agents come from visitors and could contain markup."""
        return html.escape(str(x)[:n])

    rows = []
    for v in people[:40]:
        pages = ", ".join(f"{p}" + (f" x{c}" if c > 1 else "") for p, c in v["pages"].most_common(6))
        rows.append((v["first"].strftime("%H:%M"), v["ip"], v.get("owner", ""), v["where"] or "unknown",
                     pages, v["requests"], v["ua"]))
    activity_lines = [
        ("Unique visitors (people) / page views", f"{len(people)} / {views}"),
        ("Chat questions answered", e.get("message", 0)), ("Chat sessions", act["chat_sessions"]),
        ("Identity checks passed / failed", f"{e.get('verify_ok', 0)} / {e.get('verify_fail', 0)}"),
        ("Store orders (demo)", f"{act['orders']} (${act['orders_total']:.2f})"),
        ("Cipher attack runs", f"{len(act['cipher_runs'])} ({act.get('cipher_events', 0)} of Cipher's own test events, not counted above)"),
        ("Prompt injections blocked", e.get("injection_blocked", 0)),
        ("Bots and crawlers (addresses)", len(bots)),
    ]
    spend = [("AI spend today", f"${act['spend_day']:.2f} of ${SETTINGS.daily_cap_usd:.2f} daily cap"),
             ("AI spend this month", f"${act['spend_month']:.2f} of ${SETTINGS.monthly_cap_usd:.2f} monthly cap")]

    # ---- plain text
    t = [subject, "", "ANYTHING UNUSUAL"] + ([f"- {n}" for n in notes] or ["- Nothing unusual today."])
    t += ["", "VISITORS (people)"] + ([f"- {r[0]}  {r[1]}  {r[2]}  {r[3]}  pages: {r[4]}" for r in rows] or ["- none"])
    t += ["", "ACTIVITY"] + [f"- {k}: {v}" for k, v in activity_lines]
    t += ["", "SPEND"] + [f"- {k}: {v}" for k, v in spend]
    if act["cipher_runs"]:
        t += ["", "CIPHER RUNS"] + [f"- {r}" for r in act["cipher_runs"]]
    t += ["", "Web logs are kept for at most two days. Times are Eastern."]

    # ---- HTML
    def table(head, body):
        """A plain HTML table for the email (inline styles, since email clients ignore style sheets)."""
        h = "".join(f"<th style='text-align:left;padding:4px 8px;background:#eef2f7'>{esc(x)}</th>" for x in head)
        b = "".join("<tr>" + "".join(f"<td style='padding:4px 8px;border-top:1px solid #dde'>{esc(c, 160)}</td>" for c in r)
                    + "</tr>" for r in body)
        return f"<table style='border-collapse:collapse;font-size:13px'><tr>{h}</tr>{b}</table>"
    h = [f"<div style='font-family:Segoe UI,Arial,sans-serif;color:#1b1f24'><h2 style='color:#1f5fbf'>{esc(subject, 200)}</h2>",
         "<h3>Anything unusual</h3><ul>" + ("".join(f"<li>{esc(n, 300)}</li>" for n in notes) or "<li>Nothing unusual today.</li>") + "</ul>",
         "<h3>Visitors (people)</h3>" + (table(["First seen", "IP", "Network", "Location", "Pages", "Requests", "Browser"], rows)
                                         if rows else "<p>No human visitors today.</p>"),
         "<h3>Activity</h3>" + table(["", ""], activity_lines), "<h3>Spend</h3>" + table(["", ""], spend)]
    if act["cipher_runs"]:
        h.append("<h3>Cipher runs</h3><ul>" + "".join(f"<li>{esc(r, 300)}</li>" for r in act["cipher_runs"]) + "</ul>")
    h.append("<p style='color:#5b6470;font-size:12px'>Web logs are kept for at most two days. Times are Eastern. "
             "Paths and browser names come from visitors and are shown as plain text.</p></div>")
    return subject, "\n".join(t), "".join(h)


def send(subject: str, text: str, html_body: str) -> bool:
    """Email the owner through Resend. Without a key (e.g. local tests) it does nothing and returns False."""
    key = os.environ.get("RESEND_API_KEY", "")
    to = os.environ.get("REPORT_TO", "")
    if not key or not to:
        return False
    body = json.dumps({"from": os.environ.get("REPORT_FROM", "Tucker SOC <onboarding@resend.dev>"),
                       "to": [to], "subject": subject[:200], "text": text, "html": html_body}).encode()
    # Fixed HTTPS address (never visitor-supplied); the API key comes from the server's env file only.
    req = urllib.request.Request("https://api.resend.com/emails", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                                          "User-Agent": "tucker-report/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:   # noqa: S310 - fixed https:// URL above
            return 200 <= r.status < 300
    except Exception:
        return False


def warn(kind: str, detail: str) -> bool:
    """A short real-time warning email (called from alerts.py, which already limits each kind to once a day)."""
    subject = f"Tucker alert: {kind.replace('_', ' ')}"
    text = f"{detail}\n\nSent automatically by tuckerpaymentprocessing.com. Full details in tonight's report."
    return send(subject, text, f"<p>{html.escape(detail)}</p><p style='color:#5b6470'>Full details in tonight's report.</p>")


def main():
    """Build today's report; email it (the nightly timer) or print it with --print (testing)."""
    day = dt.datetime.now(ET).date()
    subject, text, html_body = build(day)
    if "--print" in sys.argv:
        print(text)
        return
    print("sent" if send(subject, text, html_body) else "NOT sent (missing RESEND_API_KEY/REPORT_TO or Resend error)")
    print(subject)


if __name__ == "__main__":
    main()
