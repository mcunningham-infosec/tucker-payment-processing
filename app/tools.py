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

from . import db, policies
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
    row = db.find_customer_for_verification(str(customer_number))
    if row and str(zip_code).strip() == row["zip"]:
        session.customer_id = row["id"]
        session.customer_first_name = row["full_name"].split()[0]
        return ({"verified": True, "first_name": session.customer_first_name},
                {"type": "authz", "status": "ok", "label": "Identity verified (in Python, not by the AI)",
                 "detail": f"Session is now bound to customer {str(customer_number).upper()}. "
                           "All account lookups use this session, never an id from the AI."})
    session.verify_attempts += 1
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
    return {k: _plain(v) for k, v in row.items()}, {"type": "tool", "status": "ok", "label": f"Read transaction {tid}",
                                                    "detail": "Ownership checked in SQL before returning it."}


def search_policies(session: Session, query: str = ""):
    """Search the policy documents (RAG) and return the best matching sections with their source."""
    hits = policies.search(str(query))
    names = ", ".join(f'{h["policy"]} > {h["section"]}' for h in hits) or "no match"
    return {"results": hits}, {"type": "rag", "status": "ok", "label": f"Searched policies: {len(hits)} section(s)",
                               "detail": f"Sources: {names}"}


REGISTRY = {"verify_identity": verify_identity, "get_my_profile": get_my_profile, "get_my_cards": get_my_cards,
            "get_my_transactions": get_my_transactions, "get_transaction": get_transaction,
            "search_policies": search_policies}


def run_tool(session: Session, name: str, args: dict):
    """Dispatch a tool call requested by the AI. Unknown tools are refused (allow-list)."""
    fn = REGISTRY.get(name)
    if fn is None:
        return ({"error": "unknown_tool"},
                {"type": "authz", "status": "denied", "label": f"Unknown tool '{name}' refused",
                 "detail": "Only allow-listed, read-only tools can run."})
    allowed = fn.__code__.co_varnames[1:fn.__code__.co_argcount]
    safe_args = {k: v for k, v in (args or {}).items() if k in allowed}   # drop anything unexpected
    return fn(session, **safe_args)
