"""
spend.py - the app-level AI spending cap (the graceful layer of cost control).

Every model call's tokens are priced and recorded. Before each new call we check the
month-to-date and day-to-date totals. Over the cap -> Tucker "takes a nap" instead of calling
the model. Google's own hard cap on the Gemini API (a Cloud Billing spend cap) sits behind this as a backstop.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
from . import alerts, db, limits
from .config import SETTINGS


def cost_of(tokens_in: int, tokens_out: int) -> float:
    """Price one model call in USD from its token counts."""
    return tokens_in / 1e6 * SETTINGS.price_in_per_m + tokens_out / 1e6 * SETTINGS.price_out_per_m


def check_caps():
    """Return (ok, details). ok is False when the monthly or daily cap has been reached."""
    month = db.ai_spend_since("month")
    day = db.ai_spend_since("day")
    details = {"month_usd": round(month, 4), "month_cap": SETTINGS.monthly_cap_usd,
               "day_usd": round(day, 4), "day_cap": SETTINGS.daily_cap_usd}
    if month >= SETTINGS.monthly_cap_usd * 0.8:
        alerts.raise_once("month_80", f"Month to date ${month:.2f} of ${SETTINGS.monthly_cap_usd:.2f}")
    elif month >= SETTINGS.monthly_cap_usd * 0.5:
        alerts.raise_once("month_50", f"Month to date ${month:.2f} of ${SETTINGS.monthly_cap_usd:.2f}")
    if month >= SETTINGS.monthly_cap_usd:
        alerts.raise_once("nap", "Monthly AI budget reached: Tucker naps until next month")
        return False, {**details, "reason": "monthly AI budget reached"}
    if day >= SETTINGS.daily_cap_usd:
        alerts.raise_once("nap", f"Daily AI budget reached (${day:.2f}): Tucker naps until midnight")
        return False, {**details, "reason": "daily AI budget reached"}
    return True, details


def record(model: str, tokens_in: int, tokens_out: int) -> float:
    """Store one call's usage and return its cost."""
    cost = cost_of(tokens_in, tokens_out)
    db.record_ai_usage(model, tokens_in, tokens_out, cost)
    return cost


def fair_share(client_ip):
    """Per-network share of the shared daily AI budget, so one abuser can't make Tucker nap for everyone.
    Normally 200 AI-answered questions a day per network; once half the day's budget is spent, new
    questions are limited to 50 per network. Only that network is affected. Returns (ok, details)."""
    if not client_ip:
        return True, ""
    busy = db.ai_spend_since("day") >= SETTINGS.daily_cap_usd / 2
    if busy:
        alerts.raise_once("busy_mode")
    n = SETTINGS.ai_questions_per_ip_when_busy if busy else SETTINGS.ai_questions_per_ip_per_day
    if limits.over_limit("ai_ip_day", client_ip, n, 86400):
        alerts.raise_once("fair_share", f"A network hit its daily AI share ({n}{', busy mode' if busy else ''})", client_ip)
        return False, (f"Your network has used its fair share today ({n} AI answers"
                       f"{', reduced while the site is busy' if busy else ''}). Other visitors are unaffected.")
    limits.record("ai_ip_day", client_ip)
    return True, f"{n} AI answers a day per network{' (busy mode)' if busy else ''}"
