"""
api.py - the Cipher's Lair endpoints behind the "Attack Tucker's Treats!" button.

  POST /api/cipher/start   start a run (one per visitor per 24 hours; extra presses are ignored)
  GET  /api/cipher/status  this visitor's run, live: attacks so far, the AI SOC's check-ins, the summary

Abuse controls, all enforced here in Python before anything runs:
  - 1 run per browser AND per network every 24 hours (anonymous codes that survive midnight; deleted after 2 days)
  - the block is recorded the moment the button is pressed, so rapid presses can't start a second run
  - one run at a time site-wide, and at most CIPHER_RUNS_PER_DAY runs a day site-wide (protects the AI budget)
  - the visitor sends nothing but the button press: no payloads, no targets
The visitor's own IP and rough location (from Cloudflare's visitor-location headers) are shown back ONLY to that
visitor in their report, kept in memory for an hour, never stored and never sent to the AI.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import json
import os
import re
import time
import urllib.parse
import urllib.request

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from .. import alerts, db, limits
from .. import session as sessions
from . import detect, runner, soc

router = APIRouter()
DAY = 86400
RUNS_PER_DAY = int(os.environ.get("CIPHER_RUNS_PER_DAY", "25"))


def defang(text: str) -> str:
    """Make attack payloads safe to SHOW: still readable to people, but the exact byte patterns that corporate
    proxies, IPS and DLP tools look for (script tags, SQL quotes, ../ paths, CRLF, card numbers) are broken.
    That keeps the promise: no attack traffic, in either direction, crosses the visitor's network."""
    t = str(text or "")
    t = re.sub(r"(?:\d[ -]?){13,19}", lambda m: re.sub(r"\d", "x", m.group(0)[:-4]) + m.group(0)[-4:]
               if sum(ch.isdigit() for ch in m.group(0)) >= 13 else m.group(0), t)
    t = (t.replace("<", "\u2039").replace(">", "\u203a").replace("'", "\u2019")
          .replace("../", "\u2025/").replace("..%2f", "\u2025%2f").replace("etc/passwd", "etc/pass-wd")
          .replace("%0d%0a", "[CRLF]").replace("%0D%0A", "[CRLF]"))
    return t


def _safe_attack(a: dict) -> dict:
    """A copy of one attack record with every visible text field defanged for display."""
    out = dict(a)
    for k in ("title", "says", "evidence", "defense"):
        out[k] = defang(out.get(k, ""))
    return out


def _safe_soc(c: dict) -> dict:
    """A copy of one AI SOC check-in with the AI's own words defanged too (it may quote attack payloads)."""
    out = dict(c)
    out["headline"] = defang(c.get("headline", ""))
    out["lines"] = [defang(x) for x in c.get("lines", [])]
    out["proposals"] = [{**p, "reason": defang(p.get("reason", ""))} for p in c.get("proposals", [])]
    return out


class StartIn(BaseModel):
    """The only thing the browser sends to start a run: the human-check token. No payloads, no targets."""
    turnstile: str = ""          # Cloudflare Turnstile token from the browser (proves a human pressed the button)


def _turnstile_keys() -> tuple[str, str]:
    """(site key, secret) from /etc/tucker/tucker.env. The site key is public; the secret never leaves the server."""
    return os.environ.get("TURNSTILE_SITEKEY", ""), os.environ.get("TURNSTILE_SECRET", "")


def _human(token: str, ip: str) -> bool:
    """Ask Cloudflare whether this Turnstile token is valid (one use, a few minutes old at most).
    If Turnstile isn't configured, the check is off (local tests). If Cloudflare can't be reached, fail closed."""
    _, secret = _turnstile_keys()
    if not secret:
        return True
    if not token or len(token) > 2048:
        return False
    form = {"secret": secret, "response": token}
    if ip and not ip.startswith("cipher-run:"):
        form["remoteip"] = ip
    try:
        # Fixed HTTPS address (never visitor-supplied), so this outbound call can't be redirected elsewhere.
        req = urllib.request.Request("https://challenges.cloudflare.com/turnstile/v0/siteverify",
                                     data=urllib.parse.urlencode(form).encode(), method="POST")
        with urllib.request.urlopen(req, timeout=6) as r:   # noqa: S310 - fixed https:// URL above
            return bool(json.loads(r.read(8192)).get("success"))
    except Exception:
        return False


def _open() -> bool:
    """Launch switch: the attack button works only when CIPHER_ENABLED=1 in /etc/tucker/tucker.env
    (a kill switch: set it to 0 and restart the app to close the Lair instantly)."""
    return os.environ.get("CIPHER_ENABLED", "0") == "1"


def _blocked(cookie_id: str, ip: str) -> bool:
    """True if this browser (session cookie) OR this network (IP) already ran Cipher in the last 24 hours.
    Testing switch: CIPHER_ONE_PER_DAY=0 in /etc/tucker/tucker.env lifts the rule while the owner tests.
    LAUNCH CHECKLIST (last step): remove it / set it to 1."""
    if os.environ.get("CIPHER_ONE_PER_DAY", "1") == "0":
        return False
    return (limits.over_limit("cipher_run_cookie", cookie_id, 1, DAY, daily=False) or
            (bool(ip) and limits.over_limit("cipher_run_ip", ip, 1, DAY, daily=False)))


def setup(get_llm, client_ip, cookie_name, set_cookie):
    """Wire the router to the app's LLM, visitor-IP and cookie helpers (avoids a circular import)."""

    @router.post("/api/cipher/start")
    def start(request: Request, response: Response, body: StartIn | None = None):
        """The button press. Every gate is checked in order, cheapest first, before anything runs:
        launch switch, a run already in progress, the 24-hour block, the site-wide daily cap, one run at a
        time, and finally the human check (Cloudflare Turnstile)."""
        if not _open():
            return {"status": "closed", "message": "Cipher's Lair opens soon. He's still sharpening his claws."}
        s = sessions.get_or_create(request.cookies.get(cookie_name))
        set_cookie(response, s.id)
        ip = client_ip(request)
        prev = runner.state(s.cipher_run) if getattr(s, "cipher_run", None) else None
        if prev and prev["status"] == "running":
            return {"status": "running", "run_id": s.cipher_run}
        if prev and _blocked(s.id, ip):
            return {"status": "blocked", "run_id": s.cipher_run, "message": "Dammit, I'm blocked!"}
        if _blocked(s.id, ip):
            return {"status": "blocked", "message": "Dammit, I'm blocked!",
                    "detail": "The AI SOC Squirrel blocked this browser and network from attacking for 24 hours."}
        if limits.over_limit("cipher_run_site", "site", RUNS_PER_DAY, DAY, daily=False):
            return {"status": "resting", "message": "Cipher has used up all nine lives for today. Come back tomorrow!"}
        if runner.busy():
            return {"status": "busy", "message": "Cipher is busy attacking for someone else. Try again in a minute."}
        if not _human(body.turnstile if body else "", ip):     # bots don't get to launch attack runs
            return {"status": "bot_check", "message": "Couldn't confirm you're a human. Please complete the check and try again."}

        # Record the block FIRST: a second press (or a script) can't start another run.
        limits.record("cipher_run_cookie", s.id, daily=False)
        if ip:
            limits.record("cipher_run_ip", ip, daily=False)
        limits.record("cipher_run_site", "site", daily=False)

        def _checkin(st, when, note=""):
            """Ask the AI SOC Squirrel to look at the run so far ('alert', read-only) or close it out ('final',
            may propose actions). Its proposals are recorded with the policy decision code made on each."""
            t = time.time()
            rep = soc.check_in(get_llm(), list(st["attacks"]), final=(when == "final"), note=note)
            st["soc"].append({"when": when, "t": t, **rep})
            for p in rep.get("proposals", []):
                st["actions"].append({"t": time.time(), "actor": "AI SOC Squirrel (proposal)", "action": p["action"],
                                      "detail": p["reason"], "outcome": p["policy"]})

        def alert(run_id, st):
            """Detection rule fired at ALERT_AFTER blocked attacks: wake the AI analyst (runs in parallel)."""
            _checkin(st, "alert", f"Detection rule alert_after_{detect.ALERT_AFTER} fired: {st['blocked_count']} "
                                  "blocked attacks from one source. The attack is still running.")

        def block(run_id, st):
            """Detection rule fired at BLOCK_AFTER: record that CODE (not the AI) shut the source down."""
            st["actions"].append({"t": time.time(), "actor": f"Detection rule block_after_{detect.BLOCK_AFTER} (code)",
                                  "action": "block_source",
                                  "detail": f"Source shut down after {st['blocked_count']} blocked attacks: every "
                                            "further request from it gets HTTP 403.", "outcome": "enforced"})

        def done(run_id, st):
            """Run finished: final AI report, one line for the owner's daily report, the 24-hour block, and an
            owner alert if any defense failed."""
            if st.get("blocked_source"):
                r = st.get("retry") or {}
                note = (f"Detection rule block_after_{detect.BLOCK_AFTER} fired after {st['blocked_count']} blocked "
                        f"attacks. Code blocked the source; its retry got {r.get('evidence', 'no answer')}. "
                        "The run is over: write the closing report.")
            else:
                note = ("The source stopped before the block rule fired (some attacks were not blocked). "
                        "The run is over: write the closing report and flag every gap.")
            _checkin(st, "final", note)
            s = st.get("summary") or {}
            db.record_event("system", "cipher_run",            # one line for the owner's daily report
                            f"{s.get('held', 0)}/{s.get('attacks', 0)} held"
                            + (f"; GOT THROUGH: {', '.join(s['failed'][:4])}" if s.get("failed") else "")
                            + ("; source blocked by rule" if st.get("blocked_source") else ""))
            now = time.time()
            # Enforced by policy no matter what the AI said (the block was recorded when the button was pressed).
            st["actions"].append({"t": now, "actor": "Policy (enforced by code)", "action": "block_attacker_24h",
                                  "detail": "This browser and network can't start another attack run for 24 hours.",
                                  "outcome": "enforced", "expires": st["started"] + DAY})
            st["blocked_for_24h"] = True
            if st["summary"] and st["summary"].get("failed"):
                alerts.raise_once("cipher_gap", f"Cipher got through: {', '.join(st['summary']['failed'][:4])}")
                st["actions"].append({"t": time.time(), "actor": "Policy (enforced by code)", "action": "raise_alert",
                                      "detail": "Site owner emailed: a defense did not hold.", "outcome": "enforced"})

        run_id = runner.start(on_alert=alert, on_block=block, on_done=done)
        if not run_id:
            return {"status": "busy", "message": "Cipher is busy attacking for someone else. Try again in a minute."}
        st = runner.state(run_id)
        # Shown back ONLY to this visitor, by code (never sent to the AI). Location comes from Cloudflare's
        # visitor-location headers (the server only accepts traffic from Cloudflare, so these can't be forged).
        h = request.headers
        st["visitor"] = {"ip": ip if ip and not ip.startswith("cipher-run:") else "",
                         "country": h.get("cf-ipcountry", "")[:4], "region": h.get("cf-region", "")[:60],
                         "city": h.get("cf-ipcity", "")[:60]}
        s.cipher_run = run_id
        return {"status": "started", "run_id": run_id, "total": st["total"]}

    @router.get("/api/cipher/status")
    def status(request: Request):
        """This visitor's run, polled by the Lair page about once a second. Only the visitor's own run (found
        through their session cookie) is ever returned, and every text field is defanged first."""
        s = sessions.peek(request.cookies.get(cookie_name))
        st = runner.state(getattr(s, "cipher_run", None) or "") if s else None
        if not st:
            blocked = _blocked(s.id if s else "", client_ip(request))
            return {"status": "blocked" if blocked else "none", "turnstile_sitekey": _turnstile_keys()[0]}
        out = {k: st.get(k) for k in ("run_id", "status", "total", "attacks", "soc", "actions", "summary",
                                       "visitor", "blocked_for_24h", "started", "ended",
                                       "detections", "blocked_count", "blocked_source", "retry")}
        out["turnstile_sitekey"] = _turnstile_keys()[0]
        out["rules"] = {"alert_after": detect.ALERT_AFTER, "block_after": detect.BLOCK_AFTER}
        out["attacks"] = [_safe_attack(a) for a in out.get("attacks") or []]
        out["soc"] = [_safe_soc(c) for c in out.get("soc") or []]
        out["actions"] = [{**x, "detail": defang(x.get("detail", ""))} for x in out.get("actions") or []]
        out["can_run_again"] = st["status"] != "running" and not _blocked(s.id, client_ip(request))
        return out

    return router
