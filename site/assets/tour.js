/*
 * tour.js - Tucker's guided tour of the site.
 *
 * A small Tucker with a speech bubble walks the visitor through the three things to try (in Cipher's Lair, Cipher
 * takes over as guide). Nothing is forced: Next just moves on, whether or not the visitor tries anything.
 *   1. the AI chat on the home page, 2. the treat store and its AI chat, 3. Cipher's Lair.
 * Each "Next" highlights the next thing on the page; when the next stop is on another page, Next goes there
 * (the step travels in the address, e.g. treats.html?tour=5, so it works even if browser storage is blocked).
 *
 * No cookies, nothing sent anywhere, no third-party code. sessionStorage only remembers "already offered the tour"
 * for this browser tab. All text is set with textContent, never as HTML.
 */
(function () {
  "use strict";

  // Which page we're on: "home", "treats" or "cipher" (from the file name; "/" is the home page).
  var file = (location.pathname.split("/").pop() || "index.html").toLowerCase();
  var PAGE = file === "treats.html" ? "treats" : file === "cipher.html" ? "cipher" : file === "index.html" ? "home" : "";

  // The tour. page = where the step happens; spot = what to highlight (a CSS selector, or none);
  // go = for the last step on a page, where Next takes the visitor.
  var STEPS = [
    { page: "home", spot: null,
      say: "Woof! I'm Tucker. Let me show you around: my chat, my treat store and Cipher's Lair. It takes about a minute, and you can close me any time." },
    { page: "home", spot: "#real-tech",
      say: "First, the important part: this is a real, live technology demonstration. The company and its customers are pretend, but nothing about the technology is fake: real AI, a real hardened server, real security controls and real attacks." },
    { page: "home", spot: ".chat-card",
      say: "This is me: a real AI support agent, powered by Google Gemini. If you like, ask me about company policies, or tap \"Verify as Penny\" and ask about her account. I only see a customer's data after code checks who they are. No need to try anything; just click Next whenever you're ready." },
    { page: "home", spot: ".chat-card .try .attack",
      say: "Feel free to try to trick me with this button. Prompt-injection attempts are caught before they ever reach the AI." },
    { page: "home", spot: ".bts",
      say: "If you do chat with me, every message shows up here step by step: the guardrail checks, what the AI was allowed to see, and what got masked on the way out." },
    { page: "home", spot: ".tabs a[href='treats.html']", go: "treats.html",
      say: "Next stop: my treat store. Click Next and I'll take you there." },

    { page: "treats", spot: ".products",
      say: "Welcome to Tucker's Treats! Pretend treats and pretend money, so there's nothing to buy, but you're welcome to fill a cart and check out to see how it works." },
    { page: "treats", spot: ".chat-card",
      say: "I work the store too. You can ask me about any treat, or try talking me into a free squirrel. I can look products up, but prices and orders are decided by code, never by me." },
    { page: "treats", spot: ".tabs a[href='cipher.html']", go: "cipher.html",
      say: "Now the fun part. My nemesis Cipher the cat lives in the Lair, and he'll show you around in there. Let's go!" },

    { page: "cipher", spot: ".lair-real", who: "cipher",
      say: "Muhahaha! Cipher here. Tucker doesn't come in my Lair, so I'm your guide now. Everything here is real: I run 50 actual attacks against this live website, from inside its own server." },
    { page: "cipher", spot: "#attack", who: "cipher",
      say: "When you're ready, press this and I'll start my attack (one per day). Watch all three boxes. It takes about 2½ minutes." },
    { page: "cipher", spot: ".lair-box.soc", who: "cipher",
      say: "That's the AI SOC Squirrel, a bounded Gemini security analyst. A detection rule wakes it, it writes your security report live, and code checks every fact it states. Annoying little rodent." },
    { page: "cipher", spot: null, last: true, who: "cipher",
      say: "That's the tour! Go on, unleash me whenever you like. When it's over, Tucker will point you to the About Us page: how this site is built, the AI policies behind it, and the code on GitHub." }
  ];

  // Who is talking in the bubble. Tucker guides, except in Cipher's Lair, where Cipher takes over.
  var GUIDES = {
    tucker: { pic: "assets/tucker_avatar_256.png", name: "Tucker" },
    cipher: { pic: "assets/cipher_avatar_256.png", name: "Cipher, a black cat" }
  };

  var OFFERED = "tucker-tour-offered";
  var bubble, picEl, textEl, countEl, backBtn, nextBtn, launcher, spotted = null, current = -1;
  var note = null;   // set while Tucker shows a one-off tip (not a tour step): where its button goes

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text) { e.textContent = text; }
    return e;
  }

  function offeredAlready() {
    try { return sessionStorage.getItem(OFFERED) === "1"; } catch (e) { return false; }
  }
  function markOffered() {
    try { sessionStorage.setItem(OFFERED, "1"); } catch (e) { /* storage blocked: the offer may show again */ }
  }

  // The bubble: small Tucker, what he says, and Back / Next / close.
  function build() {
    bubble = el("div", "tour");
    bubble.setAttribute("role", "dialog");
    bubble.setAttribute("aria-label", "Tour of the site with Tucker");
    bubble.hidden = true;

    var img = picEl = el("img", "tour-pic");
    img.width = 56; img.height = 56;

    var body = el("div", "tour-body");
    textEl = el("p", "tour-text");
    textEl.setAttribute("aria-live", "polite");
    var row = el("div", "tour-row");
    countEl = el("span", "tour-count");
    backBtn = el("button", "tour-back", "Back");
    nextBtn = el("button", "tour-next", "Next");
    backBtn.type = nextBtn.type = "button";
    row.appendChild(countEl); row.appendChild(backBtn); row.appendChild(nextBtn);
    body.appendChild(textEl); body.appendChild(row);

    var close = el("button", "tour-close", "×");
    close.type = "button";
    close.setAttribute("aria-label", "End the tour");

    bubble.appendChild(img); bubble.appendChild(body); bubble.appendChild(close);
    document.body.appendChild(bubble);

    // "Restart the Tour" sits at the end of the site's tab row, so the tour can be started again from any page.
    var tabs = document.querySelector("nav.tabs");
    launcher = el("button", "tour-tab", "Restart the Tour");
    launcher.type = "button";
    if (tabs) { tabs.appendChild(launcher); }

    nextBtn.addEventListener("click", next);
    backBtn.addEventListener("click", back);
    close.addEventListener("click", end);
    launcher.addEventListener("click", function () { show(0); });
    window.addEventListener("resize", function () { if (!bubble.hidden && current >= 0) { place(spotted); } });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !bubble.hidden) { end(); } });
  }

  function guide(who) {
    var g = GUIDES[who] || GUIDES.tucker;
    if (picEl.getAttribute("src") !== g.pic) { picEl.src = g.pic; }
    picEl.alt = g.name;
    bubble.classList.toggle("tour-cipher", who === "cipher");
  }

  function unspot() {
    if (watcher) { watcher.disconnect(); }
    if (spotted) { spotted.classList.remove("tour-spot"); spotted = null; }
  }

  // Show step i (on this page): highlight its target, scroll it into view above the bubble, update the text.
  function show(i) {
    var s = STEPS[i];
    if (!s) { return end(); }
    if (s.page !== PAGE) { location.href = pageFile(s.page) + "?tour=" + i; return; }
    current = i;
    note = null;
    unspot();
    var target = s.spot ? document.querySelector(s.spot) : null;
    if (target) {
      target.classList.add("tour-spot");
      spotted = target;
      // Re-place if the item or the page around it changes size (e.g. products or images finish loading above it).
      if (watcher) { watcher.observe(target); watcher.observe(document.body); }
    }
    guide(s.who);
    textEl.textContent = s.say;
    countEl.textContent = (i + 1) + " of " + STEPS.length;
    backBtn.hidden = i === 0;
    nextBtn.textContent = s.last ? "Done" : s.go ? "Take me there" : "Next";
    bubble.hidden = false;
    place(target);
    markOffered();
    nextBtn.focus({ preventScroll: true });
  }

  // Put the bubble right next to what the guide is talking about, never on top of it, and scroll so both are in
  // view. Preference: just below the item, then beside it (wide screens), then just above it. With nothing to
  // point at, the bubble sits in the middle of the screen.
  var watcher = window.ResizeObserver ? new ResizeObserver(function () { if (spotted && !bubble.hidden) { place(spotted); } }) : null;

  // Is the item pinned on screen while the page scrolls (CSS position:sticky, like the store's chat)?
  function pinned(node) {
    for (; node && node !== document.body; node = node.parentElement) {
      if (getComputedStyle(node).position === "sticky") { return true; }
    }
    return false;
  }

  function place(target) {
    var GAP = 14, EDGE = 10;
    bubble.classList.remove("tour-center", "tour-fixed");
    bubble.style.left = bubble.style.top = "";
    if (!target) { bubble.classList.add("tour-center"); return; }

    var vw = document.documentElement.clientWidth, vh = window.innerHeight;
    var w = bubble.offsetWidth, h = bubble.offsetHeight;
    var r = target.getBoundingClientRect();
    var clampX = function (v) { return Math.max(EDGE, Math.min(v, vw - w - EDGE)); };
    var side = vw - r.right >= w + GAP + EDGE ? "right" : r.left >= w + GAP + EDGE ? "left" : "";
    var x, y;

    if (pinned(target)) {
      // A pinned item stays put on screen, so the bubble is pinned next to it too, and nothing scrolls.
      bubble.classList.add("tour-fixed");
      if (r.bottom + GAP + h <= vh - EDGE) { x = clampX(r.left); y = r.bottom + GAP; }
      else if (side) { x = side === "right" ? r.right + GAP : r.left - w - GAP; y = Math.max(EDGE, Math.min(r.top, vh - h - EDGE)); }
      else { x = clampX(r.left); y = Math.max(EDGE, r.top - h - GAP); }
      bubble.style.left = x + "px";
      bubble.style.top = y + "px";
      return;
    }

    var x0 = r.left + window.pageXOffset, y0 = r.top + window.pageYOffset;   // item's position on the page
    var scrollTo;
    if (r.height + GAP + h + 2 * EDGE <= vh) {                    // fits below: center the pair on screen
      x = clampX(x0);
      y = y0 + r.height + GAP;
      scrollTo = y0 - (vh - (r.height + GAP + h)) / 2;
    } else if (side) {                                             // tall item: beside it
      x = side === "right" ? x0 + r.width + GAP : x0 - w - GAP;
      y = y0;
      scrollTo = y0 - 70;
    } else {                                                       // tall and full width: just above it
      x = clampX(x0);
      y = Math.max(EDGE, y0 - h - GAP);
      scrollTo = y - EDGE;
    }
    bubble.style.left = x + "px";
    bubble.style.top = y + "px";
    window.scrollTo({ top: Math.max(0, scrollTo), behavior: "smooth" });
  }

  // A one-off tip outside the numbered tour, e.g. after Cipher's attack finishes. Button goes to href.
  function tip(text, label, href) {
    unspot();
    current = -1;
    note = href;
    guide("tucker");
    textEl.textContent = text;
    countEl.textContent = "";
    backBtn.hidden = true;
    nextBtn.textContent = label;
    bubble.hidden = false;
    place(null);
  }

  function pageFile(page) { return page === "home" ? "./" : page + ".html"; }

  function next() {
    var s = STEPS[current];
    if (note) { location.href = note; return; }
    if (s && s.last) { end(); return; }
    if (s && s.go) { location.href = s.go + "?tour=" + (current + 1); return; }
    show(current + 1);
  }

  function back() {
    if (current <= 0) { return; }
    var prev = STEPS[current - 1];
    if (prev.page !== PAGE) { location.href = pageFile(prev.page) + "?tour=" + (current - 1); return; }
    show(current - 1);
  }

  function end() {
    note = null;
    unspot();
    bubble.hidden = true;
    current = -1;
    markOffered();
  }

  // The step number arriving in the address (?tour=5), if any; then tidy the address bar.
  function stepFromAddress() {
    var m = /[?&]tour=(\d{1,2})\b/.exec(location.search);
    if (!m) { return -1; }
    try { history.replaceState(null, "", location.pathname + location.hash); } catch (e) { /* keep the address */ }
    var i = parseInt(m[1], 10);
    return STEPS[i] && STEPS[i].page === PAGE ? i : -1;
  }

  function start() {
    build();
    if (!PAGE) { return; }        // e.g. About Us and checkout: just the "Restart the Tour" button
    // After Cipher's attack finishes (cipher.js fires "cipher-done"), Tucker recommends the About Us page.
    if (PAGE === "cipher") {
      document.addEventListener("cipher-done", function () {
        setTimeout(function () {
          tip("Nice work, you survived Cipher! Want to see how all of this is built? The About Us page covers the " +
              "architecture, the AI policies behind me, and the code on GitHub if you really want to dig in.",
              "Show me", "about.html");
        }, 4000);
      });
    }
    var i = stepFromAddress();
    if (i >= 0) { show(i); return; }
    // First visit to the home page this session: Tucker offers the tour (once). Otherwise just the corner button.
    if (PAGE === "home" && !offeredAlready()) { show(0); }
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", start); } else { start(); }
})();
