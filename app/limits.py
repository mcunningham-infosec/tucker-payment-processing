"""
limits.py - generous, database-backed limits that hold no matter which cookie a visitor shows up with.

Every limit is counted two ways where it matters: by the visitor's IP address and by their session cookie.
Neither is stored as-is. Each is turned into an anonymous code with an HMAC keyed by a server secret plus
today's date, so the codes change every day and can't be traced back to a person or linked across days.
Counters live in ops.usage_events and are wiped every night at midnight.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import hashlib
import hmac
import ipaddress
from datetime import date

from . import db
from .config import SETTINGS


def network(value: str) -> str:
    """The unit a per-network limit counts. IPv4: the address itself. IPv6: its /64 network, because one
    phone or one home is given a whole /64 (billions of addresses) and can switch addresses at will; counting
    single IPv6 addresses would let anyone dodge every limit by rotating. IPv4 written in IPv6 form
    (::ffff:1.2.3.4) is treated as the IPv4 address. Anything that isn't an IP (a cookie id, Cipher's run
    label) is returned unchanged."""
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return value
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def subject(value: str, daily: bool = True) -> str:
    """Anonymous code for an IP or cookie (never stored raw). Normally it changes every day; Cipher's
    24-hour attack blocks need a code that survives midnight (daily=False), and those rows are deleted
    after 2 days by the nightly reset."""
    key = (SETTINGS.hash_salt + (date.today().isoformat() if daily else "cipher-block")).encode()
    return hmac.new(key, (network(value) or "-").encode(), hashlib.sha256).hexdigest()[:24]


def over_limit(kind: str, value: str, limit: int, window_seconds: int, daily: bool = True) -> bool:
    """True if this visitor already used `limit` actions of this kind in the window."""
    return db.usage_count(kind, subject(value, daily), window_seconds) >= limit


def record(kind: str, value: str, daily: bool = True):
    """Count one action for this visitor."""
    db.record_usage(kind, subject(value, daily))
