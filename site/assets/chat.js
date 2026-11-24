/*
 * chat.js - the chat page: sends the visitor's message to /api/chat, shows Tucker's reply as a
 * speech bubble, and lists every guardrail step in the Behind the Scenes panel.
 *
 * Security notes:
 * - Every piece of text from the server or the visitor is inserted with textContent, never as HTML,
 *   so nothing typed or returned can run as code (no cross-site scripting).
 * - The only cookie is the server's session cookie (HttpOnly: this script can't even read it).
 * - No third-party scripts, no tracking. Same-origin requests only (enforced by the site's CSP).
 */
(function () {
  "use strict";

  var MAX = 500;   // must match the server's limit; the server enforces it regardless

  // Friendly names for each kind of step the server reports.
  var KINDS = {
    input: "Input check", rate: "Rate limit", injection: "Prompt-injection shield",
    spend: "Spend cap", model: "AI model (Google Gemini)", rag: "Policy search (RAG)",
    authz: "Access control (Python)", tool: "Database read (read-only)", output: "Output filter",
    session: "Session"
  };

  var log, form, msg, send, count, steps, intro, status;

  // Create an element with a class and (optionally) plain text. Text is never parsed as HTML.
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined) { e.textContent = text; }
    return e;
  }

  // Add one chat message. who = "you" | "tucker"; returns the message element.
  function addMessage(who, text, extraClass) {
    var row = el("div", "msg " + who + (extraClass ? " " + extraClass : ""));
    if (who === "tucker") {
      var img = el("img");
      img.src = "assets/tucker_avatar_256.png"; img.alt = ""; img.width = 40; img.height = 40;
      row.appendChild(img);
    }
    var say = el("div", "say");
    if (typeof text === "string") { say.textContent = text; } else { say.appendChild(text); }
    row.appendChild(say);
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
    return row;
  }

  // Little things Tucker is "doing" while the AI works on an answer.
  var BUSY = ["thinking", "sniffing through the files", "scratching an ear", "fetching that",
              "looking for his toy", "checking the policy binder"];

  // Show bouncing dots plus a dog-ish status while Tucker "thinks"; returns the element so it can be removed.
  function addTyping() {
    var wrap = el("span");
    var dots = el("span", "dots");
    dots.appendChild(el("span")); dots.appendChild(el("span")); dots.appendChild(el("span"));
    wrap.appendChild(dots);
    wrap.appendChild(el("span", "busy", " Tucker is " + BUSY[Math.floor(Math.random() * BUSY.length)] + "..."));
    return addMessage("tucker", wrap, "typing");
  }

  // Replace the Behind the Scenes list with this message's steps, revealed one after another.
  function showSteps(events) {
    steps.textContent = "";
    intro.textContent = "What happened to your last message, in order:";
    (events || []).forEach(function (ev, i) {
      var li = el("li", ev.status === "ok" ? "ok" : "denied");
      li.appendChild(el("span", "kind", KINDS[ev.type] || ev.type));
      li.appendChild(el("span", "label", ev.label || ""));
      if (ev.detail) { li.appendChild(el("span", "detail", ev.detail)); }
      li.style.animationDelay = (i * 0.12) + "s";   // CSSOM, allowed by the CSP (no inline style attribute)
      steps.appendChild(li);
    });
  }

  // Update the little status line under Tucker's name.
  function setStatus(text, napping) {
    status.textContent = text;
    status.className = "status" + (napping ? " nap" : "");
  }

  // Send one message to the server and render the result. All failures end in a friendly message.
  function sendMessage(text) {
    text = (text || "").trim();
    if (!text) { return; }
    addMessage("you", text);
    msg.value = ""; updateCount();
    send.disabled = true;
    var typing = addTyping();

    fetch("api/chat", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text.slice(0, MAX), page: page, cart: page === "cart" ? currentCart() : [] })
    })
      .then(function (r) {
        if (!r.ok) { throw new Error("HTTP " + r.status); }
        return r.json();
      })
      .then(function (data) {
        typing.remove();
        addMessage("tucker", data.reply || "", data.napping ? "nap" : "");
        showSteps(data.events);
        if (data.napping) { setStatus("taking a nap (spending cap reached)", true); }
        else if (data.verified_as) { setStatus("helping " + data.verified_as + " (verified)"); }
        else { setStatus("AI support agent · online"); }
      })
      .catch(function () {
        typing.remove();
        addMessage("tucker", "Tucker couldn't hear you just now (the connection dropped). Please try again.");
      })
      .then(function () { send.disabled = false; msg.focus({ preventScroll: true }); });
  }

  // Keep the character counter in step with the text box.
  function updateCount() { count.textContent = msg.value.length + " / " + MAX; }

  // Ask the server to forget this chat and the verified identity, then clear the screen.
  function resetChat() {
    fetch("api/reset", { method: "POST", credentials: "same-origin" })
      .catch(function () { /* nothing to do: the session also expires on its own */ })
      .then(function () {
        while (log.children.length > 1) { log.removeChild(log.lastChild); }
        showSteps([{ type: "session", status: "ok", label: "Chat reset: the server forgot this conversation",
                     detail: "Your verified identity and chat history were dropped and the session cookie was deleted." }]);
        intro.textContent = "What your last click did:";
        setStatus("AI support agent · online");
      });
  }

  // Wire everything up once the page is ready.
  // Which page's chat this is: "home" (full chat), "store" (products) or "cart" (cart + this visit's orders).
  var page = "home";

  // The cart's product codes and quantities (never prices), read from this tab's storage for the cart chat.
  function currentCart() {
    try {
      var c = JSON.parse(window.sessionStorage.getItem("tucker-cart") || "{}") || {};
      return Object.keys(c).map(function (sku) { return { sku: sku, qty: c[sku] }; });
    } catch (e) { return []; }
  }

  function init() {
    var box = document.querySelector("[data-chat-page]");
    page = box ? box.getAttribute("data-chat-page") : "home";
    log = document.getElementById("log");
    form = document.getElementById("form");
    msg = document.getElementById("msg");
    send = document.getElementById("send");
    count = document.getElementById("count");
    steps = document.getElementById("steps");
    intro = document.getElementById("bts-intro");
    status = document.getElementById("status");

    form.addEventListener("submit", function (e) { e.preventDefault(); sendMessage(msg.value); });
    // Enter sends; Shift+Enter makes a new line.
    msg.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); if (!send.disabled) { sendMessage(msg.value); } }
    });
    msg.addEventListener("input", updateCount);
    var resetBtn = document.getElementById("reset");
    if (resetBtn) { resetBtn.addEventListener("click", resetChat); }
    Array.prototype.forEach.call(document.querySelectorAll(".try button"), function (b) {
      b.addEventListener("click", function () { if (!send.disabled) { sendMessage(b.getAttribute("data-say")); } });
    });
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
