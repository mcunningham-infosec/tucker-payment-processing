"""
alerts.py - tells the site owner when a limit starts biting, so the limits can be tuned.

Each alert is ONE structured line in the app's system log, e.g.
    TUCKER_ALERT kind=fair_share who=3f9a1c... detail="Network hit its daily AI share (200)"
Something outside the app (Cloud Monitoring, see deploy/alert-policy.json) watches for that prefix and emails the owner.
- Sent at most once per day per kind (and per network, where a network is involved), so no alert storms.
- Networks appear only as the anonymous daily code from limits.subject(): never a raw IP address.
- Never raises: alerting must not break the site.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import logging
import threading

from . import limits

log = logging.getLogger("tucker.alerts")

KINDS = {
    "fair_share": "A network used up its daily AI share",
    "busy_mode": "Half of today's AI budget is used: fair-share limits tightened",
    "nap": "AI budget cap reached: Tucker is napping",
    "month_50": "Half of this month's AI budget is used",
    "month_80": "80% of this month's AI budget is used",
    "zip_lockout": "A network was locked out for guessing customer ZIP codes",
    "cipher_gap": "Cipher's live attack run got past a defense: fix it",
}


def _notify(kind: str, text: str):
    """Record the alert for the nightly report and email a short warning now, in the background so the
    visitor's request never waits on email. Same once-a-day limit as the log line above."""
    try:
        from . import db, report
        db.record_event("system", "alert", f"{kind}: {text}")
        threading.Thread(target=report.warn, args=(kind, text), daemon=True).start()
    except Exception as e:      # an alert must never break the visitor's request; the log line above still went out
        print(f"Owner alert email not sent: {type(e).__name__}", flush=True)


def raise_once(kind: str, detail: str = "", who: str = ""):
    """Log one alert line, at most once per day for this kind (and this network, if given)."""
    try:
        key = f"{kind}:{who or '-'}"
        if limits.over_limit("alert", key, 1, 86400):
            return False
        limits.record("alert", key)
        code = limits.subject(who) if who else "-"
        text = (detail or KINDS.get(kind, kind)).replace('"', "'")[:200]
        log.warning('TUCKER_ALERT kind=%s who=%s detail="%s"', kind, code, text)
        _notify(kind, text)
        return True
    except Exception:          # alerting is best-effort; the site keeps working
        return False
