"""
store.py - Tucker's Treats: the demo store's catalog, pricing and (simulated) payment authorization.

The browser only ever sends WHAT it wants (product codes and quantities). It never sends a card:
every order is "on Tucker" - his card is on file in the database. Everything that matters is decided here:
  - prices come from the database, never from the browser (anything price-like the browser sends is ignored)
  - quantities are clamped, unknown products are refused
  - the card is always Tucker's card on file; anything card-like the browser sends is ignored
  - the card must be active and unexpired, or the order is declined
  - the shipping address is the chosen demo customer's (dog-themed, fictional) address on file; nothing to type
No order is stored: the store is read-only like the rest of the site. Only a count goes to the ops log.
Every step adds a Behind the Scenes event so visitors can watch the checks happen.
"""
import datetime as dt
import secrets
from decimal import Decimal

from . import db

MAX_QTY = 5            # per product
MAX_LINES = 6          # one line per product at most
SHIP_FROM = "Tucker's Treats, 1 Not the Pound Way, Not the Pound, NJ"
TAX_RATE = Decimal("0.06625")   # New Jersey sales tax, for realism
FREE_SHIPPING_OVER = Decimal("25.00")
SHIPPING = Decimal("4.99")
DOLLARS_FIELDS = ("price", "price_usd", "unit_price", "total", "amount", "subtotal", "discount")
TUCKER_REF = "TPP-0001"          # the customer whose card pays for every Treats order


def _ev(events, type_, status, label, detail=""):
    """Append one Behind the Scenes event (same shape the chat uses)."""
    events.append({"type": type_, "status": status, "label": label, "detail": detail})


def catalog():
    """All products, in display order, exactly as stored in the database."""
    rows = db.products()
    return [{**r, "price_usd": f"{r['price_usd']:.2f}"} for r in rows]


def _clean_items(raw_items, events):
    """Validate the cart the browser sent: known SKUs only, whole-number quantities 1-5, no duplicates.
    Returns {sku: qty}. Anything price-like in the request is ignored (and reported)."""
    if not isinstance(raw_items, list) or not raw_items:
        _ev(events, "input", "denied", "Cart is empty")
        return {}
    tampered = False
    cart = {}
    for item in raw_items[:MAX_LINES * 2]:
        if not isinstance(item, dict):
            continue
        if any(k in item for k in DOLLARS_FIELDS):
            tampered = True
        sku = str(item.get("sku", ""))[:20]
        try:
            qty = int(item.get("qty", 0))
        except (TypeError, ValueError):
            qty = 0
        if qty < 1:
            continue
        cart[sku] = min(cart.get(sku, 0) + qty, MAX_QTY)
    if tampered:
        _ev(events, "tamper", "denied", "Browser tried to send its own prices - ignored",
            "Prices always come from the database on the server.")
    else:
        _ev(events, "input", "ok", "Cart received: product codes and quantities only")
    return cart


def quote(raw_items, events):
    """Price a cart from the database. Returns the priced order (lines, subtotal, tax, shipping, total)."""
    cart = _clean_items(raw_items, events)
    prices = {p["sku"]: p for p in db.products()}
    lines, unknown = [], []
    for sku, qty in cart.items():
        p = prices.get(sku)
        if not p:
            unknown.append(sku)
            continue
        lines.append({"sku": sku, "name": p["name"], "image": p["image"], "qty": qty,
                      "unit_price": p["price_usd"], "line_total": p["price_usd"] * qty})
    if unknown:
        _ev(events, "input", "denied", "Unknown product code(s) refused", ", ".join(unknown)[:80])
    subtotal = sum((l["line_total"] for l in lines), Decimal("0"))
    shipping = Decimal("0") if subtotal >= FREE_SHIPPING_OVER or not lines else SHIPPING
    tax = (subtotal * TAX_RATE).quantize(Decimal("0.01"))
    total = subtotal + shipping + tax
    if lines:
        _ev(events, "pricing", "ok", f"Priced {len(lines)} item(s) from the database",
            f"Subtotal ${subtotal:.2f} + shipping ${shipping:.2f} + NJ tax ${tax:.2f}")
    return {
        "lines": [{**l, "unit_price": f"{l['unit_price']:.2f}", "line_total": f"{l['line_total']:.2f}"} for l in lines],
        "subtotal": f"{subtotal:.2f}", "shipping": f"{shipping:.2f}", "tax": f"{tax:.2f}",
        "total": f"{total:.2f}", "ship_from": SHIP_FROM,
    }


def _authorize(events):
    """Simulated authorization on Tucker's card on file. Returns (approved, reason, card)."""
    card = db.tucker_card(TUCKER_REF)
    if not card:
        _ev(events, "payment", "denied", "Tucker's card on file wasn't found")
        return False, "Tucker misplaced his wallet. Please try again later.", None
    _ev(events, "authz", "ok", f"Paying with Tucker's card on file: {card['brand']} ending {card['last4']}",
        "The browser never sends or chooses a card.")
    today = dt.date.today()
    expired = (card["exp_year"], card["exp_month"]) < (today.year, today.month)
    if card["status"] != "active" or expired:
        _ev(events, "payment", "denied", "Declined: Tucker's card is not active")
        return False, "Declined: Tucker's card isn't active right now.", card
    return True, "", card


def shoppers():
    """Demo customers a visitor can pretend to be at checkout (no typing: picked from a list)."""
    return [{"customer_ref": r["customer_ref"], "name": r["full_name"],
             "address": f"{r['street']}, {r['city']}, {r['state']} {r['zip']}"} for r in db.demo_shoppers()]


def _check_shopper(customer_ref, events):
    """The chosen shopper must be one of the demo customers in the database. Returns their record or None."""
    ref = str(customer_ref or "").strip().upper()[:20]
    match = [s for s in shoppers() if s["customer_ref"] == ref]
    if not match:
        _ev(events, "input", "denied", "Unknown shopper refused", "Only the listed demo customers can shop.")
        return None
    _ev(events, "input", "ok", f"Shopping as {match[0]['name']} ({ref})",
        "Checked against the customer table; shipping to their address on file.")
    return match[0]


def checkout(raw_items, session_id, events, extra_fields=(), customer_ref=""):
    """Price the cart on the server, charge Tucker's card on file (simulated), return a confirmation or decline.
    extra_fields: names of anything else the browser sent (e.g. a card number) - reported and ignored."""
    priced = quote(raw_items, events)
    if not priced["lines"]:
        return {"ok": False, "message": "Your cart is empty.", "order": priced}
    shopper = _check_shopper(customer_ref, events)
    if not shopper:
        return {"ok": False, "message": "Please pick a demo customer to shop as.", "order": priced}
    if extra_fields:
        _ev(events, "tamper", "denied", "Browser sent extra fields - ignored", ", ".join(sorted(extra_fields))[:80])
    approved, reason, card = _authorize(events)
    if not approved:
        db.record_event(session_id, "order_declined", "")
        return {"ok": False, "message": reason, "order": priced}
    confirmation = "TT-" + secrets.token_hex(3).upper()
    _ev(events, "payment", "ok", f"Approved: ${priced['total']} on {card['brand']} ending {card['last4']}",
        "Simulated authorization - no real money moves.")
    _ev(events, "privacy", "ok", "Order not stored", "The store is read-only; only an anonymous count is logged.")
    db.record_event(session_id, "order_approved", "")
    return {"ok": True, "message": f"Order {confirmation} for {shopper['name']} approved and paid by Tucker! "
                                   f"Shipping to {shopper['address']}.",
            "confirmation": confirmation, "order": priced,
            "paid_with": f"{card['brand']} ending {card['last4']}"}
