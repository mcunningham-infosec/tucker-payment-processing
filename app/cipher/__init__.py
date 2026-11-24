"""
cipher - Cipher the hacker cat's live attack demo (the "Cipher's Lair" page).

Cipher attacks THIS site from inside the server: every request goes through Apache on the server's own
loopback address, so visitors' networks never carry attack traffic (no corporate proxy will flag them).
His attack list and his target are fixed in code: a visitor can't choose payloads or point him elsewhere.

Each run gets its own signed identity (X-Cipher-Run header). The app counts that run's limits on their
own, so one visitor's run can't lock out the next one. The signature uses the server's secret (HASH_SALT),
so nobody outside can forge it to dodge their own limits.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import hashlib
import hmac
import secrets

from ..config import SETTINGS

HEADER = "x-cipher-run"


def _sign(run_id: str) -> str:
    """HMAC-SHA256 of the run id with the server's secret: only this server can produce a valid signature."""
    return hmac.new(SETTINGS.hash_salt.encode(), f"cipher-run:{run_id}".encode(), hashlib.sha256).hexdigest()[:32]


def new_run_token() -> tuple[str, str]:
    """A fresh run id and the signed header value Cipher sends with every request in that run."""
    run_id = secrets.token_hex(8)
    return run_id, f"{run_id}.{_sign(run_id)}"


_BLOCKED: set = set()      # run sources the SOC's block rule shut down (in memory; runs expire in an hour)


def block_run(run_id: str):
    """The SOC's block rule fired: from now on the app refuses every request from this run (HTTP 403)."""
    _BLOCKED.add(run_id)


def forget_run(run_id: str):
    """Drop an expired run's block (its signed token is useless after the run ends, so nothing is unblocked early)."""
    _BLOCKED.discard(run_id)


def is_blocked(run_id: str | None) -> bool:
    """True if this run was shut down by the block rule. Checked by middleware in main.py on every request."""
    return bool(run_id) and run_id in _BLOCKED


def verify_run_header(value: str | None) -> str | None:
    """Return the run id if the header carries a valid signature, else None (forged or absent)."""
    if not value or "." not in value or len(value) > 80:
        return None
    run_id, sig = value.split(".", 1)
    if hmac.compare_digest(sig, _sign(run_id)):
        return run_id
    return None
