"""
detect.py - the SOC's detection rules: when to wake the AI analyst, and when to shut a source down.

Real SOCs don't page an analyst for one blocked request (that's noise) and don't block on a single hit.
They count what the DEFENSES actually did to one source and act on thresholds. Same here:

  RULE alert_after_15  - 15 blocked attacks from one source  -> wake the AI SOC Squirrel (read-only)
  RULE burst          - 8 attacks within 6 seconds from one source -> flagged as automated tooling (a scanner),
                                                               not a person; the SOC log records the escalation
  RULE block_after_100 - 100 blocked attacks from one source -> code blocks the source (HTTP 403 from then on)
                                                               and wakes the AI SOC for its final report

The counts come from the real defense responses to each request (a 403, a refused chat, a rejected price),
keyed to the source's signed identity. They don't come from Cipher's script: if a defense fails, that
attack isn't counted as blocked (it's escalated as a gap instead), and the block rule only fires on what
was really stopped.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import os
import time

ALERT_AFTER = int(os.environ.get("SOC_ALERT_AFTER", "15"))
BLOCK_AFTER = int(os.environ.get("SOC_BLOCK_AFTER", "100"))
BURST_COUNT = int(os.environ.get("SOC_BURST_COUNT", "8"))
BURST_SECONDS = float(os.environ.get("SOC_BURST_SECONDS", "6"))
PROGRESS_EVERY = 25


def _burst(st: dict, attack: dict) -> list[str]:
    """Speed rule: many attacks in a few seconds means automated tooling, not a person typing. Fires once."""
    times = st.setdefault("_times", [])
    times.append(attack.get("t") or time.time())
    recent = [t for t in times if times[-1] - t <= BURST_SECONDS]
    if st.get("burst_fired") or len(recent) < BURST_COUNT:
        return []
    st["burst_fired"] = True
    st["detections"].append({"t": time.time(), "rule": "burst", "count": len(recent), "limit": BURST_COUNT,
                             "source": f"cipher-run:{st['run_id'][:8]}", "fired": True,
                             "outcome": f"{len(recent)} attacks in {BURST_SECONDS:g}s: automated tooling, escalated"})
    return ["burst"]


def observe(st: dict, attack: dict) -> list[str]:
    """Count one attack's outcome against its source; return the rules that just fired."""
    burst = _burst(st, attack)                    # speed counts every attack, held or not
    if attack.get("held") is not True:            # only what the defenses really blocked counts toward the block
        return burst
    n = st["blocked_count"] = st.get("blocked_count", 0) + 1
    src = f"cipher-run:{st['run_id'][:8]}"
    fired = []
    if n == ALERT_AFTER:
        fired.append("alert")
        st["detections"].append({"t": time.time(), "rule": f"alert_after_{ALERT_AFTER}", "count": n,
                                 "limit": ALERT_AFTER, "source": src, "fired": True,
                                 "outcome": "AI SOC Squirrel woken (read-only)"})
    elif n == BLOCK_AFTER:
        fired.append("block")
        st["detections"].append({"t": time.time(), "rule": f"block_after_{BLOCK_AFTER}", "count": n,
                                 "limit": BLOCK_AFTER, "source": src, "fired": True,
                                 "outcome": "source BLOCKED by code (HTTP 403 from now on)"})
    elif n > ALERT_AFTER and n % PROGRESS_EVERY == 0:
        st["detections"].append({"t": time.time(), "rule": f"block_after_{BLOCK_AFTER}", "count": n,
                                 "limit": BLOCK_AFTER, "source": src, "fired": False, "outcome": "watching"})
    return burst + fired
