"""
config.py - all settings in one place, read from environment variables.

Secrets (the Gemini API key and the database password) come ONLY from the server's
environment file, never from this repository. Every limit that protects cost or abuse
is a named setting here so it can be shown on the About page and changed in one spot.
"""
import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    """Read one environment variable, falling back to a safe default."""
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    """Immutable bundle of settings; frozen so nothing can change them at runtime."""
    gemini_api_key: str = _env("GEMINI_API_KEY", "")            # secret: server env file only
    gemini_model: str = _env("GEMINI_MODEL", "gemini-3.5-flash-lite")
    database_url: str = _env("DATABASE_URL", "postgresql:///tucker?host=/var/run/postgresql")

    # Model pricing (USD per 1M tokens) used for the app-level spend cap.
    price_in_per_m: float = float(_env("PRICE_IN_PER_M", "0.30"))
    price_out_per_m: float = float(_env("PRICE_OUT_PER_M", "2.50"))

    # Cost guardrails. Google's own hard cap on the Gemini API is $9/month;
    # the app stops first, at $8, so visitors see "Tucker's taking a nap" instead of an error.
    monthly_cap_usd: float = float(_env("MONTHLY_CAP_USD", "8.00"))
    daily_cap_usd: float = float(_env("DAILY_CAP_USD", "0.75"))

    # Abuse guardrails.
    max_message_chars: int = int(_env("MAX_MESSAGE_CHARS", "500"))
    max_msgs_per_minute: int = int(_env("MAX_MSGS_PER_MINUTE", "8"))
    max_msgs_per_session: int = int(_env("MAX_MSGS_PER_SESSION", "40"))
    max_tool_rounds: int = int(_env("MAX_TOOL_ROUNDS", "4"))


SETTINGS = Settings()
