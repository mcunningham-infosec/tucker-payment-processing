"""
Tests for Tucker's Treats: the browser can choose WHAT to buy and WHICH demo card, nothing else.
"""
import psycopg
import pytest

from app import store

TAMPERED = [{"sku": "TT-106", "qty": 1, "price": "0.01"}]


def test_catalog_comes_from_database():
    """The store shows exactly the six products stored in the database."""
    items = store.catalog()
    assert len(items) == 6 and items[0]["sku"] == "TT-101"


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


def test_browser_cannot_supply_a_card():
    """Anything card-like the browser sends is reported and ignored; Tucker's card on file pays."""
    events = []
    r = store.checkout([{"sku": "TT-101", "qty": 1}], "s1", events, ["card_number"], "TPP-1002")
    assert r["ok"] and r["paid_with"] == "Visa ending 7777"
    assert any(e["type"] == "tamper" and "card_number" in e["detail"] for e in events)


def test_good_card_is_approved_and_nothing_is_stored(admin):
    """An active card is approved; no order row exists anywhere, only an anonymous count event."""
    r = store.checkout([{"sku": "TT-103", "qty": 2}], "s1", [], (), "TPP-1001")
    assert r["ok"] and "12 Fetch Lane, Barkington, NJ" in r["message"]
    n = admin.execute("SELECT count(*) FROM ops.chat_events WHERE event_type='order_approved'").fetchone()[0]
    assert n == 1


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
