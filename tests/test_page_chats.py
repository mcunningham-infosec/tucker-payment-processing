"""
Tests for the store and cart chats: least privilege per page.
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
