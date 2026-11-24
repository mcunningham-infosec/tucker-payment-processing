/*
 * store.js - Tucker's Treats: cart badge (every page), product grid (treats.html) and checkout (checkout.html).
 *
 * How it stays tamper-proof:
 * - The cart kept in this browser holds only product codes and quantities, never prices.
 * - Every price, total and approval comes from the server (/api/quote, /api/checkout), which reads the database.
 * - No card is ever entered or sent: every order is "on Tucker" (his card is on file on the server).
 * - All text from the server is inserted with textContent, never as HTML.
 * - The cart lives in sessionStorage (cleared when the browser session ends); if storage is blocked,
 *   it falls back to memory for this page. Nothing is sent anywhere until you check out.
 */
(function () {
  "use strict";

  var KEY = "tucker-cart";
  var memoryCart = {};           // fallback if sessionStorage is unavailable
  var KINDS = {
    input: "Input check", tamper: "Tamper check", pricing: "Server-side pricing", authz: "Card on file",
    payment: "Payment authorization (simulated)", privacy: "Privacy", catalog: "Database read (read-only)", database: "Database write (one locked door)",
    browser: "Your browser only", server: "Sent to server"
  };
  var localSteps = [];   // running list of steps on pages where clicks happen without a server call

  // ---------- small helpers ----------

  // Create an element with a class and optional plain text (never parsed as HTML).
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined) { e.textContent = text; }
    return e;
  }

  // Read the cart ({sku: qty}); any storage error means an empty cart.
  function getCart() {
    try { return JSON.parse(window.sessionStorage.getItem(KEY) || "{}") || {}; } catch (e) { return memoryCart; }
  }

  // Save the cart and refresh the badge in the header.
  function setCart(cart) {
    Object.keys(cart).forEach(function (k) { if (!(cart[k] > 0)) { delete cart[k]; } });
    memoryCart = cart;
    try { window.sessionStorage.setItem(KEY, JSON.stringify(cart)); } catch (e) { /* memory only */ }
    updateBadge();
  }

  // Cart as the list the server expects: [{sku, qty}].
  function cartItems(cart) {
    return Object.keys(cart).map(function (sku) { return { sku: sku, qty: cart[sku] }; });
  }

  // Show the number of items on the cart icon (upper right of every page).
  function updateBadge() {
    var badge = document.getElementById("cart-count");
    if (!badge) { return; }
    var cart = getCart(), n = 0;
    Object.keys(cart).forEach(function (k) { n += cart[k]; });
    badge.textContent = String(n);
    badge.hidden = n === 0;
  }

  // POST JSON to the API and return the parsed reply.
  function post(url, body) {
    return fetch(url, { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) { if (!r.ok) { throw new Error("HTTP " + r.status); } return r.json(); });
  }

  // Fill the Behind the Scenes list with the server's events.
  function showSteps(events) {
    var steps = document.getElementById("steps"), intro = document.getElementById("bts-intro");
    if (!steps) { return; }
    steps.textContent = "";
    if (intro) { intro.textContent = "What the server checked, in order:"; }
    (events || []).forEach(function (ev, i) {
      var li = el("li", ev.status === "ok" ? "ok" : "denied");
      li.appendChild(el("span", "kind", KINDS[ev.type] || ev.type));
      li.appendChild(el("span", "label", ev.label || ""));
      if (ev.detail) { li.appendChild(el("span", "detail", ev.detail)); }
      li.style.animationDelay = (i * 0.12) + "s";
      steps.appendChild(li);
    });
    scrollSteps(steps, (events || []).length);
  }

  // Keep the newest Behind the Scenes step in view, like a chat (scrolls the panel, never the page).
  function scrollSteps(steps, count) {
    var box = steps.closest(".bts");
    if (!box) { return; }
    var go = function () { box.scrollTop = box.scrollHeight; };
    go(); window.setTimeout(go, count * 120 + 250);
  }

  // Add one step to the running Behind the Scenes list (newest first, last 8 kept).
  function addStep(type, status, label, detail) {
    localSteps.push({ type: type, status: status, label: label, detail: detail || "" });
    localSteps = localSteps.slice(-8);
    showSteps(localSteps);
    var intro = document.getElementById("bts-intro");
    if (intro) { intro.textContent = "What your clicks did, newest at the bottom:"; }
  }

  // ---------- product grid (treats.html) ----------

  // Build one product card from the database row the server sent.
  function productCard(p) {
    var card = el("article", "product");
    var img = el("img");
    img.src = "assets/products/" + p.image; img.alt = p.name; img.width = 240; img.height = 180; img.loading = "lazy";
    card.appendChild(img);
    card.appendChild(el("span", "kind-tag " + p.kind, p.kind));
    card.appendChild(el("h3", "", p.name));
    card.appendChild(el("p", "blurb", p.blurb));
    var paws = el("div", "paws", "🐾".repeat(p.tucker_rating));
    paws.setAttribute("aria-label", "Tucker rates it " + p.tucker_rating + " out of 5");
    card.appendChild(paws);
    var row = el("div", "buy-row");
    row.appendChild(el("span", "price", "$" + p.price_usd));
    var btn = el("button", "add", "Add to cart");
    btn.type = "button";
    btn.addEventListener("click", function () {
      var cart = getCart();
      var before = cart[p.sku] || 0;
      cart[p.sku] = Math.min(before + 1, 5);
      setCart(cart);
      if (before >= 5) {
        addStep("input", "denied", "Limit reached: 5 of " + p.name, "The server enforces the same limit at checkout.");
      } else {
        addStep("browser", "ok", "Added " + p.sku + " to your cart (now " + cart[p.sku] + ")",
                "Stored in this browser tab as product code + quantity only. No price, nothing sent to the server yet.");
      }
      btn.textContent = "Added ✓";
      window.setTimeout(function () { btn.textContent = "Add to cart"; }, 1200);
    });
    row.appendChild(btn);
    card.appendChild(row);
    return card;
  }

  // Load the catalog from the server (which reads the database) and draw the grid.
  function initShop() {
    var grid = document.getElementById("products");
    fetch("api/products", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        grid.textContent = "";
        data.products.forEach(function (p) { grid.appendChild(productCard(p)); });
        addStep("catalog", "ok", "Loaded " + data.products.length + " products from the database",
                "GET /api/products - read-only database account; the page shows exactly what the table holds.");
      })
      .catch(function () { grid.textContent = "Tucker dropped the treat bag. Please refresh the page."; });
  }

  // ---------- checkout (checkout.html) ----------

  // Middle panel when there's nothing to pay for: an empty cart, or right after an order (done = true).
  function showPayEmpty(show, done) {
    var box = document.getElementById("pay-empty");
    if (!box) { return; }
    box.hidden = !show;
    if (done) {
      document.getElementById("pay-empty-title").textContent = "Thanks for shopping!";
      document.getElementById("pay-empty-text").textContent = "Your receipt is on the right, and Tucker's chat on the left can tell you about the order. Room for one more treat?";
    }
  }

  // Draw the server-priced order: lines with +/- buttons, then the totals.
  function renderOrder(order) {
    var list = document.getElementById("lines"), totals = document.getElementById("totals");
    list.textContent = ""; totals.textContent = "";
    var empty = !order.lines.length;
    document.getElementById("empty").hidden = !empty;
    document.getElementById("pay").hidden = empty;
    showPayEmpty(empty, false);
    order.lines.forEach(function (l) {
      var row = el("li", "line");
      var img = el("img"); img.src = "assets/products/" + l.image; img.alt = ""; img.width = 72; img.height = 54;
      row.appendChild(img);
      var mid = el("div", "line-mid");
      mid.appendChild(el("strong", "", l.name));
      mid.appendChild(el("span", "muted", "$" + l.unit_price + " each"));
      var qty = el("div", "qty");
      [["−", -1], ["+", 1]].forEach(function (pair, i) {
        var b = el("button", "qbtn", pair[0]); b.type = "button";
        b.setAttribute("aria-label", (pair[1] < 0 ? "One fewer " : "One more ") + l.name);
        b.addEventListener("click", function () { changeQty(l.sku, pair[1]); });
        if (i === 1) { qty.appendChild(el("span", "qn", String(l.qty))); }
        qty.appendChild(b);
      });
      mid.appendChild(qty);
      row.appendChild(mid);
      row.appendChild(el("span", "line-total", "$" + l.line_total));
      list.appendChild(row);
    });
    [["Subtotal", order.subtotal], ["Shipping", order.shipping === "0.00" ? "FREE" : "$" + order.shipping],
     ["NJ sales tax", "$" + order.tax], ["Total", "$" + order.total]].forEach(function (pair, i) {
      var row = el("div", "trow" + (i === 3 ? " grand" : ""));
      row.appendChild(el("span", "", pair[0]));
      row.appendChild(el("span", "", pair[1].charAt(0) === "$" || pair[1] === "FREE" ? pair[1] : "$" + pair[1]));
      totals.appendChild(row);
    });
  }

  // Ask the server to price the current cart.
  function refreshQuote() {
    return post("api/quote", { items: cartItems(getCart()) })
      .then(function (d) { renderOrder(d.order); showSteps(d.events); })
      .catch(function () { setResult(false, "Couldn't reach the store. Please try again."); });
  }

  // Add or remove one of a product, then re-price on the server.
  function changeQty(sku, delta) {
    var cart = getCart();
    cart[sku] = Math.max(0, Math.min((cart[sku] || 0) + delta, 5));
    setCart(cart);
    refreshQuote();
  }

  // Show the outcome banner.
  function setResult(ok, text) {
    var r = document.getElementById("result");
    r.hidden = false; r.className = "result " + (ok ? "ok" : "bad"); r.textContent = text;
  }

  // Place the order. cheat=true adds fake prices and a made-up card to prove the server ignores them.
  function placeOrder(cheat) {
    var items = cartItems(getCart()).map(function (it) {
      if (cheat) { it.price = "0.01"; }
      return it;
    });
    var body = { items: items, customer_ref: document.getElementById("shopper").value };
    if (cheat) { body.card_number = "4111 1111 1111 1111"; }   // a well-known TEST number, never a real card
    var btn = document.getElementById("place"); btn.disabled = true;
    post("api/checkout", body)
      .then(function (d) {
        showSteps(d.events);
        if (window.tuckerChatStatus && "verified_as" in d) { window.tuckerChatStatus(d.verified_as); }
        renderOrder(d.order);
        setResult(d.ok, d.ok ? d.message + " Total $" + d.order.total + " on Tucker's " + d.paid_with + "." : d.message);
        if (d.ok) {
          setCart({});
          document.getElementById("pay").hidden = true;
          showPayEmpty(true, true);
          var orderBox = document.querySelector("[aria-label='Your order']");
          orderBox.classList.add("receipt");
          orderBox.querySelector("h2").textContent = "Receipt";
        }
      })
      .catch(function () { setResult(false, "Couldn't reach the store. Please try again."); })
      .then(function () { btn.disabled = false; });
  }

  // Fill the "Shopping as" list with the demo customers from the database (no typing).
  var shopperList = [];

  // Show the chosen shopper's (fictional) address as the ship-to.
  function showShipTo() {
    var ref = document.getElementById("shopper").value;
    var s = shopperList.filter(function (x) { return x.customer_ref === ref; })[0];
    if (!s) { return; }
    document.getElementById("ship-name").textContent = s.name;
    document.getElementById("ship-to").textContent = s.address;
  }

  function loadShoppers() {
    fetch("api/shoppers", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        shopperList = d.shoppers;
        var sel = document.getElementById("shopper");
        d.shoppers.forEach(function (s) {
          var o = el("option", "", s.name + " (" + s.customer_ref + ")"); o.value = s.customer_ref; sel.appendChild(o);
        });
        // If this browser verified as a customer in Tucker's chat, shop as them by default.
        return fetch("api/whoami", { credentials: "same-origin" }).then(function (r) { return r.json(); })
          .then(function (w) {
            if (w.customer_ref && shopperList.some(function (s) { return s.customer_ref === w.customer_ref; })) {
              sel.value = w.customer_ref;
              addStep("authz", "ok", "Shopping as " + w.verified_as + ", the customer you verified as",
                      "Pre-selected from your verified chat session. Picking someone else signs you out of " + w.verified_as + "'s identity.");
            }
          }).catch(function () {});
      })
      .then(function () { showShipTo(); });
  }

  // Wire up the checkout page.
  function initCheckout() {
    refreshQuote();
    loadShoppers();
    document.getElementById("shopper").addEventListener("change", function (e) {
      showShipTo();
      showSteps([{ type: "browser", status: "ok", label: "Now shopping as " + e.target.options[e.target.selectedIndex].text,
                   detail: "Only the customer number is sent at checkout; the server checks it's a real demo customer and ships to their address on file." }]);
    });
    document.getElementById("place").addEventListener("click", function () { placeOrder(false); });
    document.getElementById("tamper").addEventListener("click", function () { placeOrder(true); });
  }

  // ---------- start ----------

  function init() {
    updateBadge();
    var page = document.body.getAttribute("data-page");
    if (page === "shop") { initShop(); }
    if (page === "checkout") { initCheckout(); }
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
