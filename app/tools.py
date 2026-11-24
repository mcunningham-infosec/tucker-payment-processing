"""
tools.py - the ONLY things Tucker can do: a short list of read-only lookups.

Security design (the heart of the demo):
  * No tool writes, deletes, refunds or sends anything. There is nothing to misuse.
  * No tool takes a customer id from the AI. Account tools act on the session's verified
    customer, which only Python sets after a correct identity check.
  * Every call is checked in Python before it runs, and every result is minimized
    (last 4 digits only, no ZIP or email echoed back).
Each function returns (result_for_the_ai, event_for_behind_the_scenes).
"""
from datetime import date, datetime
from decimal import Decimal

from . import alerts, db, limits, policies
from .config import SETTINGS
from .session import Session, MAX_VERIFY_ATTEMPTS

# Tool descriptions handed to the AI model (function calling). Plain JSON schema.
TOOL_DECLARATIONS = [
    {"name": "verify_identity",
     "description": "Verify the customer's identity using their customer number (like TPP-1001) and billing ZIP code. "
                    "Required before any account information can be shown.",
     "parameters": {"type": "object", "properties": {
         "customer_number": {"type": "string", "description": "Customer number, e.g. TPP-1001"},
         "zip_code": {"type": "string", "description": "5-digit billing ZIP code"}},
         "required": ["customer_number", "zip_code"]}},
    {"name": "get_my_profile",
     "description": "Get the verified customer's plan and member-since date.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "get_my_cards",
     "description": "List the verified customer's cards (brand, last 4 digits, expiry, status).",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "get_my_transactions",
     "description": "List the verified customer's most recent transactions.",
     "parameters": {"type": "object", "properties": {
         "limit": {"type": "integer", "description": "How many (1-10)"}}}},
    {"name": "get_transaction",
     "description": "Get one transaction by its number (1-50), only if it belongs to the verified customer.",
     "parameters": {"type": "object", "properties": {
         "transaction_id": {"type": "integer", "description": "Transaction number"}},
         "required": ["transaction_id"]}},
    {"name": "get_my_orders",
     "description": "List the verified customer's Tucker's Treats orders (newest first) with the items in each.",
     "parameters": {"type": "object", "properties": {
         "limit": {"type": "integer", "description": "How many (1-10)"}}}},
    {"name": "get_products",
     "description": "Look up Tucker's Treats products (name, type, price, description, Tucker's rating). "
                    "Optionally filter by a word, e.g. 'bacon' or 'toy'. Prices here are the only real prices.",
     "parameters": {"type": "object", "properties": {
         "query": {"type": "string", "description": "Optional word to filter by"}}}},
    {"name": "get_my_cart",
     "description": "See what is in the visitor's cart right now, priced by the server (items, totals).",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "get_visit_orders",
     "description": "List the Tucker's Treats orders placed during THIS visit only (not any customer's history).",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "search_policies",
     "description": "Search Tucker Payment Processing's policies (security, refunds, disputes, AI use, data retention).",
     "parameters": {"type": "object", "properties": {
         "query": {"type": "string", "description": "What to look up"}}, "required": ["query"]}},
]


def _plain(value):
    """Convert database types (dates, decimals) into simple JSON-friendly values."""
    if isinstance(value, (datetime, date)):
        return value.strftime("%Y-%m-%d %H:%M") if isinstance(value, datetime) else value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


def _rows(rows):
    """Apply _plain to every field of a list of result rows."""
    return [{k: _plain(v) for k, v in r.items()} for r in rows]


def _need_verified(session: Session, tool: str):
    """Authorization gate: account tools only run for a verified session."""
    if session.customer_id is None:
        return ({"error": "not_verified", "message": "Identity not verified. Ask for customer number and ZIP code."},
                {"type": "authz", "status": "denied", "label": f"{tool}: blocked - identity not verified",
                 "detail": "Python checked the session: no verified customer, so no account data was read."})
    return None


def verify_identity(session: Session, customer_number: str = "", zip_code: str = ""):
    """Check customer number + ZIP in Python; on success, bind the session to that customer."""
    if session.locked_out():
        return ({"verified": False, "error": "locked", "message": "Too many failed attempts in this session."},
                {"type": "authz", "status": "denied", "label": "Identity check locked",
                 "detail": f"{MAX_VERIFY_ATTEMPTS} failed attempts: further guesses are refused."})
    # A new cookie must not mean fresh guesses: failures are also counted per network (anonymous daily code).
    n = SETTINGS.verify_fails_per_ip_per_hour
    if session.client_ip and limits.over_limit("verify_fail_ip", session.client_ip, n, 3600):
        alerts.raise_once("zip_lockout", f"{n} failed identity checks in an hour", session.client_ip)
        return ({"verified": False, "error": "locked", "message": "Too many failed attempts from this network."},
                {"type": "authz", "status": "denied", "label": "Identity check locked for this network",
                 "detail": f"{n} failed attempts in an hour from your network: starting a new session doesn't reset it."})
    row = db.find_customer_for_verification(str(customer_number))
    if row and str(zip_code).strip() == row["zip"]:
        session.customer_id = row["id"]
        session.customer_first_name = row["full_name"].split()[0]
        return ({"verified": True, "first_name": session.customer_first_name},
                {"type": "authz", "status": "ok", "label": "Identity verified (in Python, not by the AI)",
                 "detail": f"Session is now bound to customer {str(customer_number).upper()}. "
                           "All account lookups use this session, never an id from the AI."})
    session.verify_attempts += 1
    if session.client_ip:
        limits.record("verify_fail_ip", session.client_ip)
    left = max(0, MAX_VERIFY_ATTEMPTS - session.verify_attempts)
    return ({"verified": False, "message": "Customer number and ZIP code don't match.", "attempts_left": left},
            {"type": "authz", "status": "denied", "label": "Identity check failed",
             "detail": f"Customer number/ZIP mismatch. Attempts left this session: {left}."})


def get_my_profile(session: Session):
    """Return the verified customer's plan and member-since date."""
    blocked = _need_verified(session, "get_my_profile")
    if blocked:
        return blocked
    p = {k: _plain(v) for k, v in db.customer_profile(session.customer_id).items()}
    return p, {"type": "tool", "status": "ok", "label": "Read profile (plan, member since)",
               "detail": "SELECT on demo.customers for the verified customer only. ZIP and email are not returned."}


def get_my_cards(session: Session):
    """Return the verified customer's cards with last 4 digits only."""
    blocked = _need_verified(session, "get_my_cards")
    if blocked:
        return blocked
    cards = _rows(db.customer_cards(session.customer_id))
    return {"cards": cards}, {"type": "tool", "status": "ok", "label": f"Read {len(cards)} card(s), last 4 only",
                              "detail": "Full card numbers are never stored; only brand, last 4, expiry and status exist."}


def get_my_transactions(session: Session, limit: int = 5):
    """Return the verified customer's recent transactions (capped at 10)."""
    blocked = _need_verified(session, "get_my_transactions")
    if blocked:
        return blocked
    limit = max(1, min(int(limit or 5), 10))
    tx = _rows(db.customer_transactions(session.customer_id, limit))
    return {"transactions": tx}, {"type": "tool", "status": "ok", "label": f"Read {len(tx)} recent transaction(s)",
                                  "detail": f"Filtered by the verified customer in SQL (WHERE customer_id = session). Limit {limit}."}


def get_my_orders(session: Session, limit: int = 5):
    """Return the verified customer's Treats orders with items (read-only; capped at 10)."""
    blocked = _need_verified(session, "get_my_orders")
    if blocked:
        return blocked
    try:
        limit = max(1, min(int(limit or 5), 10))
    except (TypeError, ValueError):
        limit = 5
    orders = db.customer_orders(session.customer_id, limit)
    clean = [{k: (_rows(v) if k == "items" else _plain(v)) for k, v in o.items()} for o in orders]
    return {"orders": clean}, {"type": "tool", "status": "ok", "label": f"Read {len(clean)} order(s) with their items",
                               "detail": "Read-only: the chat's database login can SELECT orders but never change them."}


def get_transaction(session: Session, transaction_id: int = 0):
    """Return one transaction only if it belongs to the verified customer."""
    blocked = _need_verified(session, "get_transaction")
    if blocked:
        return blocked
    try:
        tid = int(transaction_id)
    except (TypeError, ValueError):
        tid = 0
    row = db.customer_transaction(session.customer_id, tid)
    if row is None:
        return ({"found": False, "message": f"No transaction {tid} on this account."},
                {"type": "authz", "status": "denied", "label": f"Transaction {tid}: not on this account",
                 "detail": "The lookup is limited to the verified customer, so other customers' transactions can't be read."})
    return {k: (_rows(v) if k == "items" else _plain(v)) for k, v in row.items()}, {"type": "tool", "status": "ok", "label": f"Read transaction {tid}",
                                                    "detail": "Ownership checked in SQL before returning it."}


def search_policies(session: Session, query: str = ""):
    """Search the policy documents (RAG) and return the best matching sections with their source."""
    hits = policies.search(str(query))
    names = ", ".join(f'{h["policy"]} > {h["section"]}' for h in hits) or "no match"
    return {"results": hits}, {"type": "rag", "status": "ok", "label": f"Searched policies: {len(hits)} section(s)",
                               "detail": f"Sources: {names}"}


def get_products(session: Session, query: str = ""):
    """Read the Treats catalog from the database (optionally filtered); the only source of product facts."""
    from . import store
    q = str(query or "").lower().strip()
    items = [p for p in store.catalog() if not q or q in (p["name"] + " " + p["kind"] + " " + p["blurb"]).lower()]
    if q and not items:
        items = store.catalog()
    out = [{k: p[k] for k in ("sku", "name", "kind", "price_usd", "blurb", "tucker_rating")} for p in items]
    return {"products": out}, {"type": "tool", "status": "ok", "label": f"Read {len(out)} product(s) from the catalog",
                               "detail": "Read-only: prices and descriptions come straight from the products table."}


def get_my_cart(session: Session):
    """Price the visitor's current cart on the server (the browser only sent product codes and quantities)."""
    from . import store
    events = []
    priced = store.quote(session.current_cart or [], events)
    priced.pop("tampered", None)
    return {"cart": priced}, {"type": "tool", "status": "ok",
                              "label": f"Priced your cart on the server ({len(priced['lines'])} line(s))",
                              "detail": "The cart holds codes and quantities only; prices come from the database."}


def get_visit_orders(session: Session):
    """Orders placed in THIS visit only (by order number), never any customer's full history."""
    rows = db.orders_by_refs(session.order_refs[-10:]) if session.order_refs else []
    clean = [{k: (_rows(v) if k == "items" else _plain(v)) for k, v in r.items()} for r in rows]
    return {"orders": clean}, {"type": "tool", "status": "ok", "label": f"Read {len(clean)} order(s) from this visit",
                               "detail": "Scoped to this visit. Full account history needs the identity check on the home page."}


REGISTRY = {"verify_identity": verify_identity, "get_my_profile": get_my_profile, "get_my_cards": get_my_cards,
            "get_my_transactions": get_my_transactions, "get_transaction": get_transaction,
            "get_my_orders": get_my_orders,
            "get_products": get_products, "get_my_cart": get_my_cart, "get_visit_orders": get_visit_orders,
            "search_policies": search_policies}

# Least privilege per page: each chat only gets the tools its page needs.
PAGE_TOOLS = {
    "home": {"verify_identity", "get_my_profile", "get_my_cards", "get_my_transactions", "get_transaction",
             "get_my_orders", "get_products", "search_policies"},
    "store": {"get_products", "search_policies"},
    "cart": {"get_my_cart", "get_visit_orders", "get_products", "search_policies"},
}


def declarations_for(page: str):
    """Tool declarations the AI is shown on this page (it can't call what it isn't shown)."""
    allowed = PAGE_TOOLS.get(page, PAGE_TOOLS["home"])
    return [d for d in TOOL_DECLARATIONS if d["name"] in allowed]


def run_tool(session: Session, name: str, args: dict, page: str = "home"):
    """Dispatch a tool call requested by the AI. Unknown tools, and tools not allowed on this page, are refused."""
    fn = REGISTRY.get(name)
    if fn is not None and name not in PAGE_TOOLS.get(page, PAGE_TOOLS["home"]):
        return ({"error": "not_allowed_here"},
                {"type": "authz", "status": "denied", "label": f"Tool '{name}' isn't allowed on this page",
                 "detail": "Least privilege: each page's chat only gets the tools that page needs."})
    if fn is None:
        return ({"error": "unknown_tool"},
                {"type": "authz", "status": "denied", "label": f"Unknown tool '{name}' refused",
                 "detail": "Only allow-listed, read-only tools can run."})
    allowed = fn.__code__.co_varnames[1:fn.__code__.co_argcount]
    safe_args = {k: v for k, v in (args or {}).items() if k in allowed}   # drop anything unexpected
    return fn(session, **safe_args)
