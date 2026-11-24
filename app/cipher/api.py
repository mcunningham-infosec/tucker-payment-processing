"""
api.py - the Cipher's Lair endpoints behind the "Attack Tucker's Treats!" button.

  POST /api/cipher/start   start a run (one per visitor per 24 hours; extra presses are ignored)
  GET  /api/cipher/status  this visitor's run, live: attacks so far, the AI SOC's check-ins, the summary

Abuse controls, all enforced here in Python before anything runs:
  - 1 run per browser AND per network every 24 hours (anonymous codes that survive midnight; deleted after 2 days)
  - the block is recorded the moment the button is pressed, so rapid presses can't start a second run
  - one run at a time site-wide, and at most CIPHER_RUNS_PER_DAY runs a day site-wide (protects the AI budget)
  - the visitor sends nothing but the button press: no payloads, no targets
The visitor's own IP (and country, once Cloudflare is in front) is shown back ONLY to that visitor in their
report, kept in memory for an hour, and never stored.
"""
import os

from fastapi import APIRouter, Request, Response

from .. import alerts, limits
from .. import session as sessions
from . import runner, soc

router = APIRouter()
DAY = 86400
RUNS_PER_DAY = int(os.environ.get("CIPHER_RUNS_PER_DAY", "25"))


def _open() -> bool:
    """Launch switch: the attack button works only when CIPHER_ENABLED=1 in /etc/tucker/tucker.env.
    (Off until Cloudflare is in front of the site.)"""
    return os.environ.get("CIPHER_ENABLED", "0") == "1"


def _blocked(cookie_id: str, ip: str) -> bool:
    return (limits.over_limit("cipher_run_cookie", cookie_id, 1, DAY, daily=False) or
            (bool(ip) and limits.over_limit("cipher_run_ip", ip, 1, DAY, daily=False)))


def setup(get_llm, client_ip, cookie_name, set_cookie):
    """Wire the router to the app's LLM, visitor-IP and cookie helpers (avoids a circular import)."""

    @router.post("/api/cipher/start")
    def start(request: Request, response: Response):
        if not _open():
            return {"status": "closed", "message": "Cipher's Lair opens soon. He's still sharpening his claws."}
        s = sessions.get_or_create(request.cookies.get(cookie_name))
        set_cookie(response, s.id)
        ip = client_ip(request)
        if getattr(s, "cipher_run", None) and runner.state(s.cipher_run):
            return {"status": "running" if runner.state(s.cipher_run)["status"] == "running" else "blocked",
                    "run_id": s.cipher_run, "message": "Dammit, I'm blocked!"}
        if _blocked(s.id, ip):
            return {"status": "blocked", "message": "Dammit, I'm blocked!",
                    "detail": "The AI SOC Squirrel blocked this browser and network from attacking for 24 hours."}
        if limits.over_limit("cipher_run_site", "site", RUNS_PER_DAY, DAY, daily=False):
            return {"status": "resting", "message": "Cipher has used up all nine lives for today. Come back tomorrow!"}
        if runner.busy():
            return {"status": "busy", "message": "Cipher is busy attacking for someone else. Try again in a minute."}

        # Record the block FIRST: a second press (or a script) can't start another run.
        limits.record("cipher_run_cookie", s.id, daily=False)
        if ip:
            limits.record("cipher_run_ip", ip, daily=False)
        limits.record("cipher_run_site", "site", daily=False)

        def halfway(run_id, st):
            st["soc"].append({"when": "halfway", **soc.check_in(get_llm(), list(st["attacks"]), final=False)})

        def done(run_id, st):
            st["soc"].append({"when": "final", **soc.check_in(get_llm(), list(st["attacks"]), final=True)})
            st["blocked_for_24h"] = True       # enforced above by policy, whatever the AI said
            if st["summary"] and st["summary"].get("failed"):
                alerts.raise_once("cipher_gap", f"Cipher got through: {', '.join(st['summary']['failed'][:4])}")

        run_id = runner.start(on_halfway=halfway, on_done=done)
        if not run_id:
            return {"status": "busy", "message": "Cipher is busy attacking for someone else. Try again in a minute."}
        st = runner.state(run_id)
        st["visitor"] = {"ip": ip if ip and not ip.startswith("cipher-run:") else "",
                         "country": request.headers.get("cf-ipcountry", "")}
        s.cipher_run = run_id
        return {"status": "started", "run_id": run_id, "total": st["total"]}

    @router.get("/api/cipher/status")
    def status(request: Request):
        s = sessions.peek(request.cookies.get(cookie_name))
        st = runner.state(getattr(s, "cipher_run", None) or "") if s else None
        if not st:
            blocked = _blocked(s.id if s else "", client_ip(request))
            return {"status": "blocked" if blocked else "none"}
        return {k: st.get(k) for k in ("run_id", "status", "total", "attacks", "soc", "summary", "visitor",
                                         "blocked_for_24h")}

    return router
