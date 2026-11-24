"""
session.py - per-visitor conversation state, kept in server memory.

Each browser gets a random session id (in one strictly necessary, HttpOnly cookie).
The session holds WHO has been verified. That's the key security decision: the AI never
says whose data to fetch; the application looks it up from the verified session.
Sessions expire after 30 minutes of inactivity and nothing here is written to disk.
"""
import secrets
import time
from dataclasses import dataclass, field

SESSION_TTL_SECONDS = 30 * 60
MAX_VERIFY_ATTEMPTS = 3


@dataclass
class Session:
    """Everything we remember about one visitor's chat, only while it's active."""
    id: str
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    customer_id: int | None = None          # set ONLY by a successful identity check
    customer_first_name: str | None = None
    verify_attempts: int = 0
    message_times: list = field(default_factory=list)
    message_count: int = 0
    history: list = field(default_factory=list)   # recent (role, text) pairs for context

    def locked_out(self) -> bool:
        """True after too many failed identity checks (stops guessing)."""
        return self.verify_attempts >= MAX_VERIFY_ATTEMPTS and self.customer_id is None


_SESSIONS: dict[str, Session] = {}


def get_or_create(session_id: str | None) -> Session:
    """Return the visitor's live session, or start a new one with a fresh random id."""
    _expire_old()
    s = _SESSIONS.get(session_id or "")
    if s is None:
        s = Session(id=secrets.token_urlsafe(24))
        _SESSIONS[s.id] = s
    s.last_seen = time.time()
    return s


def reset(session_id: str | None):
    """Forget a visitor's session (the 'start over' button)."""
    _SESSIONS.pop(session_id or "", None)


def _expire_old():
    """Drop sessions idle longer than the time limit."""
    cutoff = time.time() - SESSION_TTL_SECONDS
    for sid in [k for k, v in _SESSIONS.items() if v.last_seen < cutoff]:
        _SESSIONS.pop(sid, None)
