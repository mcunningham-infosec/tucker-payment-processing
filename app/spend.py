"""
spend.py - the app-level AI spending cap (the graceful layer of cost control).

Every model call's tokens are priced and recorded. Before each new call we check the
month-to-date and day-to-date totals. Over the cap -> Tucker "takes a nap" instead of calling
the model. Google's own hard cap on the Gemini API ($9/month) sits behind this as a backstop.
"""
from . import db
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
    if month >= SETTINGS.monthly_cap_usd:
        return False, {**details, "reason": "monthly AI budget reached"}
    if day >= SETTINGS.daily_cap_usd:
        return False, {**details, "reason": "daily AI budget reached"}
    return True, details


def record(model: str, tokens_in: int, tokens_out: int) -> float:
    """Store one call's usage and return its cost."""
    cost = cost_of(tokens_in, tokens_out)
    db.record_ai_usage(model, tokens_in, tokens_out, cost)
    return cost
