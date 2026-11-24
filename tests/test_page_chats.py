"""
Tests for the store and cart chats: least privilege per page.

Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
"""
from app import store, tools
from app.chat import handle_message
from app.llm import FakeLLM, ModelTurn
from app.session import Session


def test_store_chat_cannot_reach_account_tools():
    """On the store page, even a verified session's card lookup is refused: the tool isn't allowed there."""
    s = Session(id="st1")
    tools.run_tool(s, "verify_identity", {"customer_number": "TPP-1001", "zip_code": "07731"}, "home")
    result, ev = tools.run_tool(s, "get_my_cards", {}, "store")
    assert ev["status"] == "denied" and "isn't allowed on this page" in ev["label"]
    names = {d["name"] for d in tools.declarations_for("store")}
    assert names == {"get_products", "search_policies"}


def test_products_come_from_the_database():
    """Product answers are grounded in the catalog table."""
    result, ev = tools.run_tool(Session(id="p"), "get_products", {"query": "bacon"}, "store")
    assert ev["status"] == "ok" and result["products"][0]["name"] == "Bacon Strips"
    assert result["products"][0]["price_usd"] == "7.49"


def test_cart_chat_sees_the_cart_priced_by_the_server():
    """The cart chat prices the browser's cart from the database; a fake price in the cart is ignored."""
    llm = FakeLLM([ModelTurn(tool_calls=[("get_my_cart", {})], tokens_in=10, tokens_out=5),
                   ModelTurn(text="You have a nap pillow.", tokens_in=10, tokens_out=5)])
    s = Session(id="c1")
    r = handle_message(s, "what's in my cart?", llm, None, "cart", [{"sku": "TT-106", "qty": 1, "price": "0.01"}])
    result, _ = tools.run_tool(s, "get_my_cart", {}, "cart")
    assert result["cart"]["lines"][0]["unit_price"] == "24.99"
    assert any("Priced your cart" in e["label"] for e in r["events"])


def test_visit_orders_only_show_this_visit():
    """The cart chat lists only orders placed in this session, never the customer's order history."""
    s = Session(id="v1")
    r = store.checkout([{"sku": "TT-108", "qty": 1}], s.id, [], (), "TPP-1001", "203.0.113.20")
    s.order_refs.append(r["confirmation"])
    result, ev = tools.run_tool(s, "get_visit_orders", {}, "cart")
    assert [o["order_ref"] for o in result["orders"]] == [r["confirmation"]]
    result2, _ = tools.run_tool(Session(id="v2"), "get_visit_orders", {}, "cart")
    assert result2["orders"] == []


def test_store_chat_knows_a_verified_visitors_first_name_but_nothing_else():
    """Penny verified on the home page: the store chat may greet her by name, but still has no account tools."""
    from app.chat import handle_message
    from app.llm import FakeLLM, ModelTurn
    from app.session import Session
    s = Session(id="penny-store")
    s.customer_id, s.customer_first_name = 1, "Penny"
    seen = {}

    class Spy(FakeLLM):
        def generate(self, system, messages, decl):
            seen["system"], seen["tools"] = system, [d["name"] for d in decl]
            return ModelTurn(text="Hi Penny!", tokens_in=10, tokens_out=3)

    handle_message(s, "who am i?", Spy([]), "203.0.113.50", page="store")
    assert "first name is Penny" in seen["system"]
    assert not any(n in seen["tools"] for n in ("get_my_cards", "get_my_transactions", "get_my_profile"))


def _verified_client(main, FakeLLM, ModelTurn):
    """A browser that verified as Penny (TPP-1001) in the home chat."""
    from fastapi.testclient import TestClient
    main.get_llm = lambda: FakeLLM([
        ModelTurn(tool_calls=[("verify_identity", {"customer_number": "TPP-1001", "zip_code": "07731"})], tokens_in=10, tokens_out=5),
        ModelTurn(text="Hi Penny!", tokens_in=10, tokens_out=5)])
    c = TestClient(main.app, base_url="https://testserver")
    c.post("/api/chat", json={"message": "I'm TPP-1001, ZIP 07731"})
    return c


def test_verified_person_follows_the_visitor_and_shopping_as_yourself_keeps_it():
    from app import main
    from app.llm import FakeLLM, ModelTurn
    c = _verified_client(main, FakeLLM, ModelTurn)
    assert c.get("/api/whoami").json() == {"verified_as": "Penny", "customer_ref": "TPP-1001"}
    d = c.post("/api/checkout", json={"items": [{"sku": "TT-101", "qty": 1}], "customer_ref": "TPP-1001"}).json()
    assert d["ok"] and d["verified_as"] == "Penny"


def test_shopping_as_someone_else_signs_you_out_never_in():
    """Picking Hank at checkout proves nothing: it must not grant Hank's account, so Penny is signed out."""
    from app import main
    from app.llm import FakeLLM, ModelTurn
    c = _verified_client(main, FakeLLM, ModelTurn)
    d = c.post("/api/checkout", json={"items": [{"sku": "TT-101", "qty": 1}], "customer_ref": "TPP-1005"}).json()
    assert d["ok"] and d["verified_as"] is None
    assert any("Verified as Penny, bought as Hank: signed out" in e["label"] for e in d["events"])
    assert "Hit the home page to verify again" in d["message"]
    assert c.get("/api/whoami").json()["verified_as"] is None
