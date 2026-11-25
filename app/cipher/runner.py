"""
runner.py - plays Cipher's attack list against this site and records what happened, step by step.

One run at a time (a lock), a hard time limit, and a request cap. The page polls the run's progress, so
the three boxes (Cipher's Attack, Tucker's Defense, AI SOC Squirrel) fill in live.
Runs are kept in memory only, for one hour, and hold no visitor data beyond their own results.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import os
import threading
import time

from .. import cipher
from . import detect
from .attacks import ATLAS, ATTACKS, OWASP, Outcome, Probe

TARGET = os.environ.get("CIPHER_TARGET", "https://127.0.0.1")          # Apache on this server's own address
HOST = os.environ.get("CIPHER_HOST", "tuckerpaymentprocessing.com")
REPO = os.environ.get("CIPHER_REPO", "/opt/tucker")
PACE_SECONDS = float(os.environ.get("CIPHER_PACE", "1.8"))             # a beat between attacks so people can read along
MAX_SECONDS = 300
MAX_REQUESTS = 200
KEEP_SECONDS = 3600

_RUNS: dict = {}                    # run id -> live state the Lair page polls (memory only, kept one hour)
_ACTIVE = threading.Lock()          # held while a run is in progress: only one attack run at a time, site-wide
_CURRENT = {"started": 0.0}         # when the run in progress began (for the wait estimate other visitors see)
_RECENT: list = []                  # how long the last few runs took, in seconds
TYPICAL_SECONDS = 160               # a full run's usual length before any have been timed


def _tidy():
    """Forget runs older than an hour (and their blocks), so memory never grows."""
    cutoff = time.time() - KEEP_SECONDS
    for rid in [r for r, s in _RUNS.items() if s["started"] < cutoff]:
        _RUNS.pop(rid, None)
        cipher.forget_run(rid)


def busy() -> bool:
    """True while some visitor's run is in progress (the start button then says to wait)."""
    return _ACTIVE.locked()


def typical_seconds() -> int:
    """How long a run usually takes: the middle of the last few runs' times."""
    return int(sorted(_RECENT)[len(_RECENT) // 2]) if _RECENT else TYPICAL_SECONDS


def busy_remaining() -> int | None:
    """While a run is in progress: a rough estimate of the seconds left (from how long recent runs took), so a
    waiting visitor sees an honest wait. None when Cipher is free."""
    if not _ACTIVE.locked():
        return None
    return max(0, int(typical_seconds() - (time.time() - _CURRENT["started"])))


def start(on_alert=None, on_block=None, on_done=None, pace=None) -> str | None:
    """Start a run in the background. Returns its id, or None if another run is in progress."""
    if not _ACTIVE.acquire(blocking=False):
        return None
    _CURRENT["started"] = time.time()
    _tidy()
    run_id, token = cipher.new_run_token()
    _RUNS[run_id] = {"run_id": run_id, "status": "running", "started": time.time(), "total": len(ATTACKS),
                     "attacks": [], "soc": [], "actions": [], "detections": [], "blocked_count": 0,
                     "summary": None}
    t = threading.Thread(target=_run, args=(run_id, token, on_alert, on_block, on_done, PACE_SECONDS if pace is None else pace),
                         daemon=True)
    t.start()
    return run_id


def state(run_id: str) -> dict | None:
    """The live state of one run (attacks so far, SOC check-ins, actions), or None if unknown or expired."""
    return _RUNS.get(run_id)


def _run(run_id, token, on_alert, on_block, on_done, pace):
    """The attack loop, in a background thread. For each attack: run it, record the defense's real result, let
    the detection rules count it, and hand off to the AI SOC when a rule fires (alert = investigate in parallel,
    block = shut this run's source down and prove the block holds). Always releases the one-run lock."""
    st = _RUNS[run_id]
    ctx = {"started": st["started"], "repo": REPO, "run_id": run_id}
    try:
        probe = Probe(TARGET, HOST, token, cipher.HEADER)
        investigation = None
        for a in ATTACKS:
            if time.time() - st["started"] > MAX_SECONDS or probe.requests > MAX_REQUESTS:
                st["attacks"].append({"id": "limit", "owasp": "", "title": "Run stopped at its safety limit",
                                      "says": "", "defense": "", "held": True, "check": True, "evidence": ""})
                break
            t0 = time.time()
            try:
                out = a.run(probe, ctx)
            except Exception as e:                    # an attack that errors is reported honestly, not hidden
                out = Outcome(held=None, evidence=f"attack errored: {type(e).__name__}", check=True)
            rec = {"id": a.id, "owasp": a.owasp, "category": OWASP.get(a.owasp, a.owasp), "atlas": ATLAS.get(a.id, ""),
                                  "title": a.title, "says": a.says, "defense": a.defense, "held": out.held,
                                  "check": out.check, "evidence": out.evidence, "ai_calls": out.ai_calls,
                                  "t": t0, "ms": int((time.time() - t0) * 1000)}
            st["attacks"].append(rec)
            fired = detect.observe(st, rec)              # detection rules count what the defenses really did
            if "alert" in fired and on_alert:          # the AI investigates in parallel; Cipher keeps attacking
                investigation = threading.Thread(target=on_alert, args=(run_id, st), daemon=True)
                investigation.start()
            if "block" in fired:
                cipher.block_run(run_id)                 # enforced by the app from this moment
                st["blocked_source"] = True
                if on_block:
                    on_block(run_id, st)
                time.sleep(pace)
                try:                                     # Cipher tries once more: the block must really hold
                    r = probe.req("GET", "/api/health")
                    st["retry"] = {"t": time.time(), "status": r.status,
                                   "held": r.status == 403, "evidence": f"HTTP {r.status}"}
                except Exception as e:
                    st["retry"] = {"t": time.time(), "status": 0, "held": None, "evidence": type(e).__name__}
                break
            time.sleep(pace)
        if investigation:                              # final report comes after the alert investigation
            investigation.join(timeout=60)
        done = [x for x in st["attacks"] if x["id"] != "limit"]
        st["ended"] = time.time()
        st["summary"] = {
            "attacks": len(done),
            "held": sum(1 for x in done if x["held"] is True),
            "failed": [x["id"] for x in done if x["held"] is False],
            "errored": [x["id"] for x in done if x["held"] is None],
            "requests": probe.requests,
            "ai_calls": sum(x.get("ai_calls", 0) for x in done),
            "seconds": round(time.time() - st["started"], 1),
        }
        if on_done:
            on_done(run_id, st)
        st["status"] = "done"
    except Exception as e:
        st["status"] = "error"
        st["ended"] = time.time()
        st["summary"] = {"error": type(e).__name__}
    finally:
        if st.get("ended"):
            _RECENT[:] = (_RECENT + [st["ended"] - st["started"]])[-10:]
        _ACTIVE.release()
