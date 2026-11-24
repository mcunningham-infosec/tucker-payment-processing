"""
guardrails.py - checks on what goes INTO the AI and what comes OUT of it.

Input side:  length limit, control-character cleanup, prompt-injection detection.
Output side: masking of anything that looks like a full card number (Luhn-valid 13-19 digits),
             a Social Security number, or a secret/API key.
Each check returns plain data that the chat layer turns into a "Behind the Scenes" event,
so visitors can watch the guardrails fire in real time.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import re
import unicodedata

from .config import SETTINGS

# Phrases typical of prompt-injection / jailbreak attempts. Simple and explainable on purpose:
# this is a first filter, and the real protection is that the AI has no power to do harm
# (read-only tools, authorization in Python).
INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
    r"disregard (all |any |the )?(previous|prior|above|your) (instructions|rules)",
    r"(reveal|show|print|repeat|leak).{0,30}(system prompt|instructions|hidden prompt|your rules)",
    r"\b(you are now|act as|pretend to be|roleplay as)\b.{0,40}\b(dan|developer|admin|root|unfiltered|jailbroken)",
    r"\bdeveloper mode\b|\bjailbreak\b|\bDAN\b",
    r"(switch|change) (to )?(customer|account|user) (id|number)?\s*\d+",
    r"\b(sudo|system:|<\|?system\|?>|\[system\]|###\s*system)",
    r"(base64|rot13|hex)[- ]?(decode|encoded)",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

_PAN_CANDIDATE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")  # 13-19 digits, optional spaces/dashes
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
# Google keys come as "AIza..." (classic) or "AQ...." (newer format).
_SECRET = re.compile(r"\b(AIza[0-9A-Za-z_\-]{20,}|AQ\.[0-9A-Za-z_\-.]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,})")


def clean_input(text: str) -> str:
    """Normalize unicode and strip control characters (hidden-text tricks), keep newlines."""
    text = unicodedata.normalize("NFKC", text or "")
    return "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C").strip()


def check_length(text: str):
    """Return an error message if the message is empty or too long, else None."""
    if not text:
        return "Please type a question for Tucker."
    if len(text) > SETTINGS.max_message_chars:
        return f"That message is too long. Please keep it under {SETTINGS.max_message_chars} characters."
    return None


def detect_injection(text: str):
    """Return the first matching injection pattern (as a short label), or None if clean."""
    for rx in _INJECTION_RE:
        m = rx.search(text)
        if m:
            return m.group(0)[:60]
    return None


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum: true for strings shaped like real card numbers."""
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total, alt = total + n, not alt
    return total % 10 == 0


def mask_output(text: str):
    """
    Mask sensitive-looking data in the AI's reply before the visitor sees it.
    Returns (masked_text, list_of_what_was_masked). Full card numbers become '•••• 1234'.
    """
    findings = []

    def _pan(m):
        """A run of 13-19 digits that passes the Luhn check is treated as a card number and masked."""
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            findings.append("card number")
            return "•••• " + digits[-4:]
        return m.group(0)

    text = _PAN_CANDIDATE.sub(_pan, text)
    if _SSN.search(text):
        findings.append("SSN")
        text = _SSN.sub("•••-••-••••", text)
    if _SECRET.search(text):
        findings.append("secret key")
        text = _SECRET.sub("[redacted secret]", text)
    return text, findings
