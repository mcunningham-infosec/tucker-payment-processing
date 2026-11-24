"""
main.py - the web API (FastAPI). Apache serves the static pages and forwards /api/* here.

Endpoints:
  GET  /api/health  - simple "is the app up" check
  POST /api/chat    - one message to Tucker; returns his reply plus Behind the Scenes events
  POST /api/reset   - start a fresh chat (forgets the verified customer)
The only cookie is the session id: HttpOnly (JavaScript can't read it), Secure (HTTPS only),
SameSite=Lax, and it expires when the browser closes.
"""
from fastapi import FastAPI, Request, Response
from pydantic import BaseModel

from . import session as sessions
from .chat import handle_message
from .config import SETTINGS
from .llm import GeminiLLM

app = FastAPI(title="Tucker Payment Processing", docs_url=None, redoc_url=None, openapi_url=None)
COOKIE = "tucker_session"
_llm = None


def get_llm():
    """Create the Gemini client once, on first use."""
    global _llm
    if _llm is None:
        _llm = GeminiLLM()
    return _llm


class ChatIn(BaseModel):
    """Shape of a chat request: just the visitor's message."""
    message: str


def _set_cookie(response: Response, sid: str):
    """Send the session cookie with all security flags on (session-only: no max-age)."""
    response.set_cookie(COOKIE, sid, httponly=True, secure=True, samesite="lax", path="/api")


@app.get("/api/health")
def health():
    """Liveness check used by monitoring."""
    return {"ok": True, "model": SETTINGS.gemini_model}


@app.post("/api/chat")
def chat(body: ChatIn, request: Request, response: Response):
    """Handle one chat message for this visitor's session."""
    s = sessions.get_or_create(request.cookies.get(COOKIE))
    _set_cookie(response, s.id)
    return handle_message(s, body.message[:2000], get_llm())


@app.post("/api/reset")
def reset(request: Request, response: Response):
    """Forget the visitor's chat and verified identity."""
    sessions.reset(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/api")
    return {"ok": True}
