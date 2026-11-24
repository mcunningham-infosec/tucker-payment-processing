"""
db.py - the only place the app talks to PostgreSQL.

The app's database role (tucker_app) can only SELECT the demo company's data and can only
INSERT into its own ops tables. So even if every other layer failed, a visitor (or the AI)
could not change a customer, card or transaction: the database itself refuses.
All queries use parameters (%s), never string-building, so SQL injection isn't possible here.
"""
from contextlib import contextmanager
import psycopg
from psycopg.rows import dict_row

from .config import SETTINGS


@contextmanager
def connect():
    """Open a short-lived connection (rows come back as dicts) and always close it."""
    conn = psycopg.connect(SETTINGS.database_url, row_factory=dict_row, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def connect_store():
    """Connection for the store's checkout only (tucker_store: may only call demo.place_order and log)."""
    conn = psycopg.connect(SETTINGS.store_database_url, row_factory=dict_row, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def find_customer_for_verification(customer_ref: str):
    """Return (id, name, zip) for a customer number, or None. Used only by the identity check."""
    with connect() as c:
        return c.execute("SELECT id, full_name, zip FROM demo.customers WHERE customer_ref = %s",
                         (customer_ref.strip().upper(),)).fetchone()


def customer_profile(customer_id: int):
    """Return the verified customer's non-sensitive profile (no ZIP, no email)."""
    with connect() as c:
        return c.execute("SELECT customer_ref, full_name, plan, member_since FROM demo.customers WHERE id = %s",
                         (customer_id,)).fetchone()


def customer_cards(customer_id: int):
    """Return the verified customer's cards: brand, last 4, expiry and status only."""
    with connect() as c:
        return c.execute("SELECT brand, last4, exp_month, exp_year, status FROM demo.cards "
                         "WHERE customer_id = %s ORDER BY id", (customer_id,)).fetchall()


def customer_transactions(customer_id: int, limit: int = 10):
    """Return the verified customer's most recent transactions (newest first)."""
    with connect() as c:
        return c.execute("SELECT t.id, t.created_at, t.merchant, t.amount_usd, t.status, t.decline_reason, "
                         "c.brand, c.last4, o.order_ref FROM demo.transactions t JOIN demo.cards c ON c.id = t.card_id "
                         "JOIN demo.orders o ON o.id = t.order_id "
                         "WHERE t.customer_id = %s ORDER BY t.created_at DESC LIMIT %s",
                         (customer_id, limit)).fetchall()


def customer_transaction(customer_id: int, transaction_id: int):
    """Return one transaction ONLY if it belongs to the verified customer (else None)."""
    with connect() as c:
        row = c.execute("SELECT t.id, t.created_at, t.merchant, t.amount_usd, t.status, t.decline_reason, "
                        "c.brand, c.last4, o.order_ref, t.order_id FROM demo.transactions t "
                        "JOIN demo.cards c ON c.id = t.card_id JOIN demo.orders o ON o.id = t.order_id "
                        "WHERE t.customer_id = %s AND t.id = %s", (customer_id, transaction_id)).fetchone()
        if row:
            row["items"] = c.execute("SELECT p.name, i.qty, i.unit_price FROM demo.order_items i "
                                     "JOIN demo.products p ON p.sku = i.sku WHERE i.order_id = %s",
                                     (row.pop("order_id"),)).fetchall()
        return row


def customer_orders(customer_id: int, limit: int = 5):
    """The verified customer's Tucker's Treats orders (newest first), each with its items. Read-only."""
    with connect() as c:
        orders = c.execute("SELECT id, order_ref, created_at, total, status, paid_by, source FROM demo.orders "
                           "WHERE customer_id = %s ORDER BY created_at DESC LIMIT %s", (customer_id, limit)).fetchall()
        for o in orders:
            o["items"] = c.execute("SELECT p.name, i.qty, i.unit_price FROM demo.order_items i "
                                   "JOIN demo.products p ON p.sku = i.sku WHERE i.order_id = %s",
                                   (o.pop("id"),)).fetchall()
        return orders


def record_ai_usage(model: str, tokens_in: int, tokens_out: int, cost: float):
    """Append one model call's token counts and cost (feeds the spend cap)."""
    with connect() as c:
        c.execute("INSERT INTO ops.ai_usage (model, input_tokens, output_tokens, cost_usd) VALUES (%s,%s,%s,%s)",
                  (model, tokens_in, tokens_out, cost))


def ai_spend_since(interval: str) -> float:
    """Total AI cost for the current month ('month') or day ('day'), in USD."""
    if interval not in ("month", "day"):
        raise ValueError("interval must be 'month' or 'day'")
    with connect() as c:
        row = c.execute(f"SELECT COALESCE(SUM(cost_usd),0) AS total FROM ops.ai_usage "
                        f"WHERE called_at >= date_trunc('{interval}', now())").fetchone()
        return float(row["total"])


def record_event(session_id: str, event_type: str, detail: str = ""):
    """Append a guardrail/chat event (no chat text, no IP) for the daily report."""
    with connect() as c:
        c.execute("INSERT INTO ops.chat_events (session_id, event_type, detail) VALUES (%s,%s,%s)",
                  (session_id, event_type, detail[:200]))


# ---------- Tucker's Treats (store) ----------

def products():
    """The store catalog, in display order. Prices here are the only prices that count."""
    with connect() as c:
        return c.execute("SELECT sku, name, kind, price_usd, blurb, image, tucker_rating "
                         "FROM demo.products ORDER BY sort_order").fetchall()


def tucker_card(customer_ref: str):
    """Tucker's card on file (brand, last 4, expiry, status) - the only card the store ever charges."""
    with connect() as c:
        return c.execute("SELECT ca.brand, ca.last4, ca.exp_month, ca.exp_year, ca.status FROM demo.cards ca "
                         "JOIN demo.customers cu ON cu.id = ca.customer_id "
                         "WHERE cu.customer_ref = %s ORDER BY ca.id LIMIT 1", (customer_ref,)).fetchone()


def place_order(customer_ref: str, items: list):
    """Create an order through the database's only door for it. The database re-prices everything itself."""
    import json
    with connect_store() as c:
        return c.execute("SELECT * FROM demo.place_order(%s, %s::jsonb)",
                         (customer_ref, json.dumps(items))).fetchone()


def demo_shoppers():
    """The demo customers a visitor can shop as (number and name only; Tucker himself is excluded)."""
    with connect() as c:
        return c.execute("SELECT customer_ref, full_name, street, city, state, zip FROM demo.customers "
                         "WHERE customer_ref <> 'TPP-0001' ORDER BY customer_ref").fetchall()


# ---------- Limits (anonymous daily codes only, never raw IPs) ----------

def usage_count(kind: str, subject: str, window_seconds: int) -> int:
    """How many times this anonymous visitor code did `kind` within the window."""
    with connect() as c:
        return c.execute("SELECT count(*) AS n FROM ops.usage_events WHERE kind = %s AND subject = %s "
                         "AND created_at > now() - make_interval(secs => %s)",
                         (kind, subject, window_seconds)).fetchone()["n"]


def record_usage(kind: str, subject: str):
    """Append one usage event for an anonymous visitor code."""
    with connect() as c:
        c.execute("INSERT INTO ops.usage_events (kind, subject) VALUES (%s, %s)", (kind, subject))


def orders_by_refs(refs: list):
    """Orders by order number (used for 'orders placed this visit'), newest first, with items. Read-only."""
    with connect() as c:
        orders = c.execute("SELECT id, order_ref, created_at, total, status, ship_to FROM demo.orders "
                           "WHERE order_ref = ANY(%s) ORDER BY created_at DESC", (list(refs),)).fetchall()
        for o in orders:
            o["items"] = c.execute("SELECT p.name, i.qty, i.unit_price FROM demo.order_items i "
                                   "JOIN demo.products p ON p.sku = i.sku WHERE i.order_id = %s",
                                   (o.pop("id"),)).fetchall()
        return orders
