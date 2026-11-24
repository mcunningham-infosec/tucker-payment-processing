"""
main.py - the web API (FastAPI). Apache serves the static pages and forwards /api/* here.

Endpoints:
  GET  /api/health  - simple "is the app up" check
  POST /api/chat    - one message to Tucker; returns his reply plus Behind the Scenes events
  POST /api/reset   - start a fresh chat (forgets the verified customer)
  GET  /api/products        - Tucker's Treats catalog, straight from the database
  POST /api/quote           - price a cart on the server (the browser never sets prices)
  GET  /api/shoppers        - demo customers a visitor can shop as (number and name only)
  POST /api/checkout        - price + simulated charge to Tucker's card on file; nothing is stored
The only cookie is the session id: HttpOnly (JavaScript can't read it), Secure (HTTPS only),
SameSite=Lax, and it expires when the browser closes.
"""
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import cipher
from . import session as sessions
from . import store
from .chat import handle_message
from .config import SETTINGS
from .llm import GeminiLLM

app = FastAPI(title="Tucker Payment Processing", docs_url=None, redoc_url=None, openapi_url=None)
COOKIE = "tucker_session"
MAX_BODY_BYTES = 16 * 1024      # every legitimate request here is tiny; anything bigger is refused unread
_llm = None


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Refuse oversized requests BEFORE reading them, so a flood of huge bodies can't exhaust memory.
    (Found by Cipher: Apache's limit wasn't applied to requests it forwards to the app. Now both layers check.)"""
    if request.method in ("POST", "PUT", "PATCH"):
        length = request.headers.get("content-length")
        if length is None:
            return JSONResponse({"detail": "Length required"}, status_code=411)
        if not length.isdigit() or int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
    return await call_next(request)


def get_llm():
    """Create the Gemini client once, on first use."""
    global _llm
    if _llm is None:
        _llm = GeminiLLM()
    return _llm


class ChatIn(BaseModel):
    """Shape of a chat request: the visitor's message, which page's chat it came from, and (cart page only)
    the cart's product codes and quantities so Tucker can talk about it. Prices are never accepted."""
    message: str
    page: str = "home"
    cart: list = []


def client_ip(request: Request) -> str:
    """The visitor's IP as seen by the app (Apache forwards it; uvicorn trusts only the local proxy).
    Used only to count limits as an anonymous daily code; never stored or logged by the app.
    Cipher's demo runs come from inside the server; each run carries a signed run id instead, so its
    limits are counted on their own and can't lock out real visitors (or each other)."""
    run_id = cipher.verify_run_header(request.headers.get(cipher.HEADER))
    if run_id:
        return f"cipher-run:{run_id}"
    return request.client.host if request.client else ""


def _set_cookie(response: Response, sid: str):
    """Send the session cookie with all security flags on (session-only: no max-age)."""
    response.set_cookie(COOKIE, sid, httponly=True, secure=True, samesite="lax", path="/api")


from .cipher import api as cipher_api   # noqa: E402  (needs the helpers defined above)
app.include_router(cipher_api.setup(lambda: get_llm(), client_ip, COOKIE, _set_cookie))


@app.get("/api/health")
def health():
    """Liveness check used by monitoring."""
    return {"ok": True, "model": SETTINGS.gemini_model}


@app.post("/api/chat")
def chat(body: ChatIn, request: Request, response: Response):
    """Handle one chat message for this visitor's session."""
    s = sessions.get_or_create(request.cookies.get(COOKIE))
    was_verified = s.customer_id is not None
    result = handle_message(s, body.message[:2000], get_llm(), client_ip(request), body.page[:10], body.cart[:20])
    if not was_verified and s.customer_id is not None:
        sessions.rotate(s)        # new session id the moment the visitor verifies (stops session fixation)
    _set_cookie(response, s.id)
    return result


@app.get("/api/whoami")
def whoami(request: Request):
    """Who this browser is verified as (first name and customer number only), so every page's chat and the
    checkout show the same person. Never creates a session, never returns account data."""
    s = sessions.peek(request.cookies.get(COOKIE))
    if s and s.customer_id:
        return {"verified_as": s.customer_first_name, "customer_ref": s.customer_ref}
    return {"verified_as": None, "customer_ref": None}


@app.post("/api/reset")
def reset(request: Request, response: Response):
    """Forget the visitor's chat and verified identity."""
    sessions.reset(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/api")
    return {"ok": True}


# ---------- Tucker's Treats ----------

class CartIn(BaseModel):
    """A cart as the browser sends it: a list of {sku, qty}. Extra fields are allowed so tampering can be shown."""
    items: list = []


class CheckoutIn(CartIn):
    """Checkout takes the cart and which demo customer you're shopping as. Anything else (a card number,
    a price) is reported and ignored."""
    model_config = {"extra": "allow"}
    customer_ref: str = ""


@app.get("/api/products")
def products():
    """The store catalog, exactly as stored in the database."""
    return {"products": store.catalog()}


@app.post("/api/quote")
def quote(body: CartIn):
    """Price a cart on the server and explain each step."""
    events = []
    return {"order": store.quote(body.items[:20], events), "events": events}


@app.get("/api/shoppers")
def shoppers():
    """Fictional demo customers to shop as (customer number and name only)."""
    return {"shoppers": store.shoppers()}


@app.post("/api/checkout")
def checkout(body: CheckoutIn, request: Request, response: Response):
    """Place a demo order: server-side pricing, simulated charge to Tucker's card on file."""
    s = sessions.get_or_create(request.cookies.get(COOKIE))
    _set_cookie(response, s.id)
    events = []
    extra = list((body.model_extra or {}).keys())
    result = store.checkout(body.items[:20], s.id, events, extra, body.customer_ref, client_ip(request))
    if result.get("ok"):
        s.order_refs.append(result["confirmation"])
        shopper = body.customer_ref.strip().upper()
        if s.customer_id and s.customer_ref and shopper != s.customer_ref:
            # Picking a shopper proves nothing, so it must never GRANT access to that customer's account.
            # Shopping as someone else signs the visitor out of the identity they verified instead.
            was = s.customer_first_name
            bought_as = next((x["name"].split()[0] for x in store.shoppers() if x["customer_ref"] == shopper), shopper)
            sessions.sign_out_customer(s)
            note = (f"You were verified as {was} but made this purchase as {bought_as}, so you've been signed out. "
                    "Hit the home page to verify again.")
            result["message"] = result["message"] + " " + note
            events.append({"type": "authz", "status": "ok",
                           "label": f"Verified as {was}, bought as {bought_as}: signed out",
                           "detail": "Choosing a shopper isn't proof of identity, so it never grants access to that "
                                     "customer's account. Verify again in the home page chat (customer number + ZIP)."})
    return {**result, "events": events, "verified_as": s.customer_first_name}
