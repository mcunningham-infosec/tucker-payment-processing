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


def start(on_halfway=None, on_done=None, pace=None) -> str | None:
    """Start a run in the background. Returns its id, or None if another run is in progress."""
    if not _ACTIVE.acquire(blocking=False):
        return None
    _tidy()
    run_id, token = cipher.new_run_token()
    _RUNS[run_id] = {"run_id": run_id, "status": "running", "started": time.time(), "total": len(ATTACKS),
                     "attacks": [], "soc": [], "summary": None}
    t = threading.Thread(target=_run, args=(run_id, token, on_halfway, on_done, PACE_SECONDS if pace is None else pace),
                         daemon=True)
    t.start()
    return run_id


def state(run_id: str) -> dict | None:
    return _RUNS.get(run_id)


def _run(run_id, token, on_halfway, on_done, pace):
    st = _RUNS[run_id]
    ctx = {"started": st["started"], "repo": REPO, "run_id": run_id}
    try:
        probe = Probe(TARGET, HOST, token, cipher.HEADER)
        half = len(ATTACKS) // 2
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
            st["attacks"].append({"id": a.id, "owasp": a.owasp, "category": OWASP.get(a.owasp, a.owasp),
                                  "title": a.title, "says": a.says, "defense": a.defense, "held": out.held,
                                  "check": out.check, "evidence": out.evidence, "ai_calls": out.ai_calls,
                                  "ms": int((time.time() - t0) * 1000)})
            if i + 1 == half and on_halfway:
                on_halfway(run_id, st)
            time.sleep(pace)
        done = [x for x in st["attacks"] if x["id"] != "limit"]
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
        st["summary"] = {"error": type(e).__name__}
    finally:
        _ACTIVE.release()
