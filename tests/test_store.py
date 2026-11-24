"""
Tests for Tucker's Treats: the browser can choose WHAT to buy and WHICH demo card, nothing else.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
import psycopg
import pytest

from app import store

TAMPERED = [{"sku": "TT-106", "qty": 1, "price": "0.01"}]


def test_catalog_comes_from_database():
    """The store shows exactly the eight products stored in the database."""
    items = store.catalog()
    assert len(items) == 8 and items[0]["sku"] == "TT-101"


def test_browser_prices_are_ignored():
    """A cart that tries to set its own price is priced from the database anyway, and flagged."""
    events = []
    q = store.quote(TAMPERED, events)
    assert q["lines"][0]["unit_price"] == "24.99"
    assert any(e["type"] == "tamper" for e in events)


def test_quantities_clamped_and_unknown_products_refused():
    """Quantities are capped at 5; unknown product codes and zero/negative quantities are dropped."""
    events = []
    q = store.quote([{"sku": "TT-101", "qty": 99}, {"sku": "HACK-1", "qty": 1}, {"sku": "TT-102", "qty": -3}], events)
    assert [(l["sku"], l["qty"]) for l in q["lines"]] == [("TT-101", 5)]
    assert any("Unknown product" in e["label"] for e in events)


def test_totals_are_computed_on_server():
    """Subtotal, free shipping over $25, NJ tax and total all add up."""
    q = store.quote([{"sku": "TT-106", "qty": 1}, {"sku": "TT-104", "qty": 1}], [])
    assert q["subtotal"] == "30.98" and q["shipping"] == "0.00"
    assert q["total"] == f"{30.98 + float(q['tax']):.2f}"


def test_tampered_checkout_is_refused_and_nothing_saved(admin):
    """A checkout carrying fake prices or a card number is refused outright; no order is written."""
    for items, extra in ((TAMPERED, ()), ([{"sku": "TT-101", "qty": 1}], ["card_number"])):
        events = []
        r = store.checkout(items, "s1", events, extra, "TPP-1002")
        assert not r["ok"] and r.get("refused")
        assert any(e["label"].startswith("Order refused") for e in events)
    assert admin.execute("SELECT count(*) FROM demo.orders WHERE source='web'").fetchone()[0] == 0


def test_good_order_is_saved_with_database_prices(admin):
    """An honest order is saved through demo.place_order with the database's prices, paid by Tucker."""
    r = store.checkout([{"sku": "TT-103", "qty": 2}], "s1", [], (), "TPP-1001")
    assert r["ok"] and "12 Fetch Lane, Barkington, NJ" in r["message"]
    row = admin.execute("SELECT o.total, o.paid_by, i.qty, i.unit_price FROM demo.orders o "
                        "JOIN demo.order_items i ON i.order_id = o.id WHERE o.order_ref = %s", (r["confirmation"],)).fetchone()
    assert row[1] == "tucker" and row[2] == 2 and str(row[3]) == "6.99"
    assert str(row[0]) == r["order"]["total"]          # Python's quote and the database agree to the cent


def test_store_login_can_only_call_the_function():
    """The store's own database login can't read, insert, edit or delete orders directly."""
    import os
    for sql in ("SELECT * FROM demo.orders", "UPDATE demo.orders SET total = 0", "DELETE FROM demo.order_items",
                "INSERT INTO demo.orders (order_ref, customer_id, card_id, paid_by, subtotal, shipping, tax, total, "
                "status, ship_to, source) VALUES ('X',1,1,'x',0,0,0,0,'approved','x','web')"):
        with psycopg.connect(os.environ["STORE_DATABASE_URL"], autocommit=True) as c:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(sql)


def test_chat_can_read_orders_but_never_change_them():
    """Tucker's chat login can read orders, but can't edit them or place one."""
    from app.db import connect
    with connect() as c:
        assert c.execute("SELECT count(*) FROM demo.orders").fetchone()["count"] >= 30
    for sql in ("UPDATE demo.orders SET status = 'refunded'", "SELECT demo.place_order('TPP-1001', '[]')"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with connect() as c:
                c.execute(sql)


def test_every_transaction_matches_its_order():
    """Seed data: each transaction's amount equals its Treats order's total, built from real products."""
    from app.db import connect
    with connect() as c:
        bad = c.execute("SELECT count(*) FROM demo.transactions t JOIN demo.orders o ON o.id = t.order_id "
                        "WHERE t.amount_usd <> o.total OR t.merchant <> 'Tucker''s Treats'").fetchone()["count"]
    assert bad == 0


def test_app_cannot_change_prices():
    """The app's own database account is refused if it tries to change a price."""
    from app.db import connect
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with connect() as c:
            c.execute("UPDATE demo.products SET price_usd = 0.01")


def test_must_shop_as_a_listed_demo_customer():
    """Made-up shoppers and Tucker himself can't be chosen; the list excludes Tucker."""
    assert not store.checkout([{"sku": "TT-101", "qty": 1}], "s1", [], (), "TPP-9999")["ok"]
    assert not store.checkout([{"sku": "TT-101", "qty": 1}], "s1", [], (), "TPP-0001")["ok"]
    assert "TPP-0001" not in [s["customer_ref"] for s in store.shoppers()]


def test_chat_order_lookup_is_limited_to_the_verified_customer():
    """Tucker's get_my_orders tool needs verification and only returns that customer's orders."""
    from app import tools
    from app.session import Session
    s = Session(id="t1")
    _, ev = tools.run_tool(s, "get_my_orders", {})
    assert ev["status"] == "denied"
    tools.run_tool(s, "verify_identity", {"customer_number": "TPP-1002", "zip_code": "30301"})
    store.checkout([{"sku": "TT-108", "qty": 1}], "s1", [], (), "TPP-1002")
    result, ev = tools.run_tool(s, "get_my_orders", {"limit": 10})
    assert ev["status"] == "ok" and result["orders"]
    assert result["orders"][0]["items"][0]["name"] == "Plush Squirrel"     # newest first: the web order
    from app.db import connect
    with connect() as c:
        mine = {r["order_ref"] for r in c.execute("SELECT order_ref FROM demo.orders WHERE customer_id = 2").fetchall()}
    assert {o["order_ref"] for o in result["orders"]} <= mine
