"""
Tests for the generous, cookie-proof limits and the nightly reset.
"""
import subprocess

from app import limits, store
from app.chat import handle_message
from app.config import SETTINGS
from app.llm import FakeLLM, ModelTurn
from app.session import Session

DB = ["psql", "-q", "-v", "ON_ERROR_STOP=1", "host=/var/lib/postgresql port=5433 dbname=tucker user=postgres"]


def test_cart_is_capped_at_25_items():
    """30 items requested -> trimmed to the generous 25-item cap, and the visitor is told."""
    events = []
    q = store.quote([{"sku": s, "qty": 5} for s in ("TT-101", "TT-102", "TT-103", "TT-104", "TT-105", "TT-106")], events)
    assert sum(l["qty"] for l in q["lines"]) == SETTINGS.max_cart_items
    assert any("Cart limited" in e["label"] for e in events)


def test_daily_purchase_limit_per_ip_even_with_new_cookies():
    """25 orders from one IP, then a 26th from a brand-new cookie on the same IP is refused."""
    for i in range(SETTINGS.purchases_per_day):
        assert store.checkout([{"sku": "TT-104", "qty": 1}], f"cookie-{i}", [], (), "TPP-1002", "203.0.113.7")["ok"]
    events = []
    r = store.checkout([{"sku": "TT-104", "qty": 1}], "fresh-cookie", events, (), "TPP-1002", "203.0.113.7")
    assert not r["ok"] and any("Daily purchase limit" in e["label"] for e in events)
    # a different network is unaffected
    assert store.checkout([{"sku": "TT-104", "qty": 1}], "other", [], (), "TPP-1002", "198.51.100.9")["ok"]


def test_chat_ip_limit_holds_across_sessions():
    """Dropping the cookie doesn't help: the per-IP minute limit still applies."""
    llm = FakeLLM([ModelTurn(text="Hi!", tokens_in=10, tokens_out=5)] * 40)
    ip = "192.0.2.44"
    for i in range(SETTINGS.chat_per_ip_per_minute):
        handle_message(Session(id=f"s{i}"), "hello", llm, ip)
    r = handle_message(Session(id="brand-new"), "hello", llm, ip)
    assert any(e["type"] == "rate" and e["status"] == "denied" for e in r["events"])


def test_no_raw_ip_is_stored(admin):
    """Limit counters hold anonymous daily codes, never the IP itself."""
    limits.record("purchase_ip", "203.0.113.99")
    rows = admin.execute("SELECT subject FROM ops.usage_events").fetchall()
    assert rows and all("203.0.113.99" not in r[0] for r in rows)


def test_nightly_reset_clears_today_but_keeps_spend_and_history(admin):
    """The reset removes web orders and counters but keeps the 50 historical orders and the AI spend tally."""
    store.checkout([{"sku": "TT-101", "qty": 1}], "c", [], (), "TPP-1001", "203.0.113.5")
    admin.execute("INSERT INTO ops.ai_usage (model, input_tokens, output_tokens, cost_usd) VALUES ('test', 1, 1, 0.01)")
    subprocess.run(DB + ["-f", "db/nightly_reset.sql"], check=True)
    assert admin.execute("SELECT count(*) FROM demo.orders WHERE source='web'").fetchone()[0] == 0
    assert admin.execute("SELECT count(*) FROM demo.orders WHERE source='history'").fetchone()[0] == 50
    assert admin.execute("SELECT count(*) FROM ops.usage_events").fetchone()[0] == 0
    assert admin.execute("SELECT count(*) FROM ops.ai_usage WHERE model='test'").fetchone()[0] == 1
