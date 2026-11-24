"""
Tests for the owner's daily report (app/report.py): it reads the web log correctly, tells people from bots,
flags what's unusual, and never lets visitor-controlled text (paths, browser names) inject HTML into the email.
"""
import datetime as dt

from app import report

DAY = dt.date(2026, 11, 24)
LOG = [
    '24.47.88.69 - - [24/Nov/2026:10:01:02 -0500] "GET / HTTP/2.0" 200 9143 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/131" cf="US|New Jersey|Howell"',
    '24.47.88.69 - - [24/Nov/2026:10:02:10 -0500] "GET /cipher.html HTTP/2.0" 200 6300 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/131" cf="US|New Jersey|Howell"',
    '24.47.88.69 - - [24/Nov/2026:10:02:11 -0500] "GET /assets/cipher.js HTTP/2.0" 200 13910 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/131" cf="US|New Jersey|Howell"',
    '127.0.0.1 - - [24/Nov/2026:10:05:00 -0500] "GET /.git/HEAD HTTP/1.1" 404 196 "-" "Cipher/1.0" cf="||"',
    '3.223.154.19 - - [24/Nov/2026:11:00:00 -0500] "GET /wp-login.php HTTP/1.1" 404 196 "-" "Mozilla/5.0 zgrab/0.x"',
    '3.223.154.19 - - [24/Nov/2026:11:00:01 -0500] "GET /.env HTTP/1.1" 404 196 "-" "Mozilla/5.0 zgrab/0.x"',
    '3.223.154.19 - - [24/Nov/2026:11:00:02 -0500] "GET /admin/config.php HTTP/1.1" 404 196 "-" "Mozilla/5.0 zgrab/0.x"',
    '9.9.9.9 - - [24/Nov/2026:12:00:00 -0500] "GET /index.html HTTP/1.1" 200 10 "-" "<img src=x onerror=alert(1)><script>x</script>"',
    '24.47.88.69 - - [23/Nov/2026:23:59:59 -0500] "GET / HTTP/2.0" 200 9143 "-" "Mozilla/5.0" cf="US|New Jersey|Howell"',
]
ACT = {"events": {"message": 7, "injection_blocked": 2, "verify_ok": 1, "verify_fail": 1}, "chat_sessions": 2,
       "orders": 1, "orders_total": 12.34, "alerts": ["zip_lockout: 10 failed identity checks in an hour"],
       "cipher_runs": ["50/50 held; source blocked by rule"], "spend_day": 0.05, "spend_month": 1.20}


def _entries(tmp_path):
    p = tmp_path / "access.log"
    p.write_text("\n".join(LOG) + "\n")
    return report.read_log(DAY, [str(p)])


def test_reads_only_this_day_and_skips_ciphers_loopback_traffic(tmp_path):
    e = _entries(tmp_path)
    assert {x["ip"] for x in e} == {"24.47.88.69", "3.223.154.19", "9.9.9.9"}
    assert all(x["when"].date() == DAY for x in e)
    assert [x for x in e if x["ip"] == "24.47.88.69"][0]["city"] == "Howell"


def test_people_bots_and_scanners_are_told_apart(tmp_path):
    vis = {v["ip"]: v for v in report.visitors(_entries(tmp_path), lookup=lambda ip: "TEST-NET")}
    me = vis["24.47.88.69"]
    assert not me["bot"] and me["pages"]["/cipher.html"] == 1 and me["owner"] == "TEST-NET"
    assert me["where"] == "Howell, New Jersey, US"
    assert vis["3.223.154.19"]["bot"] and vis["3.223.154.19"]["scanner"]


def test_report_flags_the_unusual_and_escapes_visitor_text(tmp_path):
    subject, text, html_body = report.build(DAY, _entries(tmp_path), ACT, lookup=lambda ip: "TEST-NET")
    assert "7 chats" in subject and "to review" in subject
    assert "probed for common weak spots" in text and "2 prompt-injection attempt(s) blocked" in text
    assert "zip_lockout" in text and "$0.05 of $0.75" in text
    assert "<script>" not in html_body and "<img" not in html_body          # visitor text can't inject HTML
    assert "&lt;img" in html_body


def test_no_key_means_no_email():
    assert report.send("s", "t", "<p>h</p>") is False
