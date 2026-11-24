"""
Test setup: point the app at a local test database (as the least-privilege tucker_app role)
and reset the ops tables before each test using an admin connection.
"""
import os
import psycopg
import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://tucker_app@/tucker?host=/var/lib/postgresql&port=5433")
ADMIN_URL = os.environ.get("ADMIN_DATABASE_URL", "postgresql://postgres@/tucker?host=/var/lib/postgresql&port=5433")


@pytest.fixture(autouse=True)
def clean_ops():
    """Empty the AI-usage and event tables so each test starts at $0 spent."""
    with psycopg.connect(ADMIN_URL, autocommit=True) as c:
        c.execute("TRUNCATE ops.ai_usage, ops.chat_events")
    yield


@pytest.fixture
def admin():
    """Admin connection for tests that need to set up special conditions (like a spent budget)."""
    with psycopg.connect(ADMIN_URL, autocommit=True) as c:
        yield c
