"""
line.py - a fair line for Cipher's Lair. Attacks are real, so only one run happens at a time, site-wide.
When Cipher is busy, a visitor who presses the button (and passes the human check) gets a place in line
instead of a race to click. When Cipher frees up, the person at the front goes next, automatically.

- First come, first served. One place per browser session; the line holds at most MAX_LINE people.
- You keep your place by having the Lair page open: it checks in every few seconds. Close the tab and you
  drop out after STALE_SECONDS, so an abandoned place never holds everyone else up.
- When it's your turn you have TURN_SECONDS to start (the page does it for you); then the next person goes.
- You passed the human check when you joined, so your turn doesn't ask again.
- Memory only, no database, no AI. Nothing about a visitor is kept beyond their session id and two times.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import threading
import time

MAX_LINE = 30
STALE_SECONDS = 20
TURN_SECONDS = 60

_LOCK = threading.Lock()
_LINE: list = []                 # session ids, front of the line first
_SEEN: dict = {}                 # session id -> last check-in (time)
_TURN = {"sid": None, "until": 0.0}


def _tidy(now: float, busy: bool):
    """Drop anyone whose page stopped checking in, and anyone whose turn ran out; hand the turn to the front."""
    for sid in [x for x in _LINE if now - _SEEN.get(x, 0) > STALE_SECONDS]:
        _LINE.remove(sid)
        _SEEN.pop(sid, None)
    if busy:
        _TURN["sid"] = None
        return
    while _LINE:
        head = _LINE[0]
        if _TURN["sid"] != head:                      # Cipher is free: the front of the line gets the turn
            _TURN["sid"], _TURN["until"] = head, now + TURN_SECONDS
            return
        if now <= _TURN["until"]:
            return
        _LINE.pop(0)                                  # turn not taken in time: next person
        _SEEN.pop(head, None)
        _TURN["sid"] = None
    _TURN["sid"] = None


def join(sid: str, busy: bool, now: float | None = None) -> int | None:
    """Put this visitor in line (or keep their place). Returns their position (1 = next), or None if full."""
    now = now or time.time()
    with _LOCK:
        _tidy(now, busy)
        if sid not in _LINE:
            if len(_LINE) >= MAX_LINE:
                return None
            _LINE.append(sid)
        _SEEN[sid] = now
        _tidy(now, busy)
        return _LINE.index(sid) + 1


def check_in(sid: str, busy: bool, now: float | None = None) -> dict | None:
    """The waiting page's regular check-in: keeps the place and reports it. None if not in line."""
    now = now or time.time()
    with _LOCK:
        if sid in _LINE:
            _SEEN[sid] = now
        _tidy(now, busy)
        if sid not in _LINE:
            return None
        pos = _LINE.index(sid) + 1
        return {"position": pos, "your_turn": _TURN["sid"] == sid,
                "turn_left": max(0, int(_TURN["until"] - now)) if _TURN["sid"] == sid else None}


def may_start(sid: str, busy: bool, now: float | None = None) -> bool:
    """Can this visitor start a run now? Yes if nobody is waiting, or if it's their turn."""
    now = now or time.time()
    with _LOCK:
        _tidy(now, busy)
        return not busy and (not _LINE or _TURN["sid"] == sid)


def in_line(sid: str) -> bool:
    """Is this visitor waiting in line (and so already passed the human check)?"""
    with _LOCK:
        return sid in _LINE


def started(sid: str):
    """This visitor's run began: they leave the line."""
    with _LOCK:
        if sid in _LINE:
            _LINE.remove(sid)
        _SEEN.pop(sid, None)
        if _TURN["sid"] == sid:
            _TURN["sid"] = None


def length(busy: bool, now: float | None = None) -> int:
    """How many people are waiting."""
    with _LOCK:
        _tidy(now or time.time(), busy)
        return len(_LINE)


def reset():
    """Empty the line (tests)."""
    with _LOCK:
        _LINE.clear()
        _SEEN.clear()
        _TURN["sid"] = None
