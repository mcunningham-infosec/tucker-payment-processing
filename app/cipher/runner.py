"""
runner.py - plays Cipher's attack list against this site and records what happened, step by step.

One run at a time (a lock), a hard time limit, and a request cap. The page polls the run's progress, so
the three boxes (Cipher's Attack, Tucker's Defense, AI SOC Squirrel) fill in live.
Runs are kept in memory only, for one hour, and hold no visitor data beyond their own results.
"""
import os
import threading
import time

from .. import cipher
from . import detect
from .attacks import ATTACKS, OWASP, Outcome, Probe

TARGET = os.environ.get("CIPHER_TARGET", "https://127.0.0.1")          # Apache on this server's own address
HOST = os.environ.get("CIPHER_HOST", "tuckerpaymentprocessing.com")
REPO = os.environ.get("CIPHER_REPO", "/opt/tucker")
PACE_SECONDS = float(os.environ.get("CIPHER_PACE", "0.9"))             # a beat between attacks so people can follow
MAX_SECONDS = 180
MAX_REQUESTS = 200
KEEP_SECONDS = 3600

_RUNS: dict = {}
_ACTIVE = threading.Lock()


def _tidy():
    cutoff = time.time() - KEEP_SECONDS
    for rid in [r for r, s in _RUNS.items() if s["started"] < cutoff]:
        _RUNS.pop(rid, None)


def busy() -> bool:
    return _ACTIVE.locked()


def start(on_alert=None, on_block=None, on_done=None, pace=None) -> str | None:
    """Start a run in the background. Returns its id, or None if another run is in progress."""
    if not _ACTIVE.acquire(blocking=False):
        return None
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
    return _RUNS.get(run_id)


def _run(run_id, token, on_alert, on_block, on_done, pace):
    st = _RUNS[run_id]
    ctx = {"started": st["started"], "repo": REPO, "run_id": run_id}
    try:
        probe = Probe(TARGET, HOST, token, cipher.HEADER)
        for i, a in enumerate(ATTACKS):
            if time.time() - st["started"] > MAX_SECONDS or probe.requests > MAX_REQUESTS:
                st["attacks"].append({"id": "limit", "owasp": "", "title": "Run stopped at its safety limit",
                                      "says": "", "defense": "", "held": True, "check": True, "evidence": ""})
                break
            t0 = time.time()
            try:
                out = a.run(probe, ctx)
            except Exception as e:                    # an attack that errors is reported honestly, not hidden
                out = Outcome(held=None, evidence=f"attack errored: {type(e).__name__}", check=True)
            rec = {"id": a.id, "owasp": a.owasp, "category": OWASP.get(a.owasp, a.owasp),
                                  "title": a.title, "says": a.says, "defense": a.defense, "held": out.held,
                                  "check": out.check, "evidence": out.evidence, "ai_calls": out.ai_calls,
                                  "t": t0, "ms": int((time.time() - t0) * 1000)}
            st["attacks"].append(rec)
            fired = detect.observe(st, rec)              # detection rules count what the defenses really did
            if "alert" in fired and on_alert:
                on_alert(run_id, st)
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
        _ACTIVE.release()
