"""
limits.py - generous, database-backed limits that hold no matter which cookie a visitor shows up with.

Every limit is counted two ways where it matters: by the visitor's IP address and by their session cookie.
Neither is stored as-is. Each is turned into an anonymous code with an HMAC keyed by a server secret plus
today's date, so the codes change every day and can't be traced back to a person or linked across days.
Counters live in ops.usage_events and are wiped every night at midnight.
"""
import hashlib
import hmac
from datetime import date

from . import db
from .config import SETTINGS


def subject(value: str) -> str:
    """Anonymous daily code for an IP or cookie (never stored raw)."""
    key = (SETTINGS.hash_salt + date.today().isoformat()).encode()
    return hmac.new(key, (value or "-").encode(), hashlib.sha256).hexdigest()[:24]


def over_limit(kind: str, value: str, limit: int, window_seconds: int) -> bool:
    """True if this visitor already used `limit` actions of this kind in the window."""
    return db.usage_count(kind, subject(value), window_seconds) >= limit


def record(kind: str, value: str):
    """Count one action for this visitor."""
    db.record_usage(kind, subject(value))
