/*
 * tour.js - Tucker's guided tour of the site.
 *
 * A small Tucker with a speech bubble walks the visitor through the three things to try (in Cipher's Lair, Cipher
 * takes over as guide). Nothing is forced: Next just moves on, whether or not the visitor tries anything.
 *   1. the AI chat on the home page, 2. the treat store and its AI chat, 3. Cipher's Lair,
 * and finishes on About Us, section by section, ending with an invitation to connect with Michael.
 * Each "Next" highlights the next thing on the page; when the next stop is on another page, Next goes there
 * (the step travels in the address, e.g. treats.html?tour=5, so it works even if browser storage is blocked).
 *
 * No cookies, nothing sent anywhere, no third-party code. sessionStorage only remembers "already offered the tour"
 * for this browser tab. All text is set with textContent, never as HTML.
 *
 * Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
 */
(function () {
  "use strict";

  // Which page we're on: "home", "treats" or "cipher" (from the file name; "/" is the home page).
  var file = (location.pathname.split("/").pop() || "index.html").toLowerCase();
  var PAGE = { "index.html": "home", "treats.html": "treats", "cipher.html": "cipher", "about.html": "about" }[file] || "";

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
    { page: "cipher", spot: null, who: "cipher", go: "about.html", label: "Show me how it's built",
      say: "That's my Lair! Unleash me whenever you're ready. When you're done here, Tucker will walk you through how this whole site is built." },

    { page: "about", spot: "#about-intro",
      say: "Welcome back, it's Tucker! This is the About Us page: how everything you just saw actually works." },
    { page: "about", spot: "#flow-chat", beside: true,
      say: "Here's how both AIs work, starting with me. Every chat message passes seven checkpoints in order, and I sit in the middle: code checks what goes in, decides whose data I may see, and masks what comes out." },
    { page: "about", spot: "#flow-soc", beside: true,
      say: "And here's the AI SOC, the AI security analyst that investigates Cipher's attacks. Code-run rules wake it, it only sees this attack's evidence, it can only propose actions from a fixed menu, and Python checks every number it states. Same pattern both times: code on both sides, the AI in the middle, never in charge." },
    { page: "about", spot: "#about-bounds",
      say: "Each AI here is bounded: what it can do, and what it can never do. Code enforces the limits, not the AI." },
    { page: "about", spot: "#about-policies",
      say: "Michael wrote the company's policies first, then built me to follow them. You can read every one on the AI Policies tab." },
    { page: "about", spot: "#about-standards",
      say: "This one matters. Michael checked this site against ten recognized standards, from the OWASP AI Top 10s and MITRE ATLAS to ISO 42001, the EU AI Act and PCI DSS: every requirement mapped to the code that proves it, and every gap admitted. They're all on the Standards tab, with PDFs." },
    { page: "about", spot: "#about-tech",
      say: "The technology underneath: Google Cloud, Gemini, Cloudflare, zero-trust admin access and least privilege everywhere." },
    { page: "about", spot: "#about-scans",
      say: "Here's our site's scorecard. Don't just take our word for it: independent scanners tested this site. The first round found three gaps, Michael fixed them the same day, and the reports went from B to A+. Every report is here as a PDF, with a link to run the scan yourself." },
    { page: "about", spot: "#about-tamper",
      say: "Every hour, a check outside the server fetches every file on this site and compares it byte for byte to GitHub. If anyone ever changes a page, Michael knows right away. Lesson learned: on its first run every page 'failed' because Cloudflare adds its own scripts, so the check had to learn exactly what Cloudflare's code looks like." },
    { page: "about", spot: "#about-code",
      say: "Want to dig deeper? Every line of code is open on GitHub. These are good places to start." },
    { page: "about", spot: "#about-who", last: true,
      say: "That's the tour, thanks for visiting! If you'd like to learn more about Michael, connect with him on LinkedIn." }
  ];

  // Who is talking in the bubble. Tucker guides, except in Cipher's Lair, where Cipher takes over.
  var GUIDES = {
    tucker: { pic: "assets/tucker_avatar_256.png", name: "Tucker" },
    cipher: { pic: "assets/cipher_avatar_256.png", name: "Cipher, a black cat" }
  };

  var OFFERED = "tucker-tour-offered";
  var bubble, picEl, textEl, tipEl, countEl, backBtn, nextBtn, launcher, spotted = null, current = -1, toured = false;
  var note = null;   // set while Tucker shows a one-off tip (not a tour step): where its button goes

  // Create an element with an optional class and TEXT content (never HTML).
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text) { e.textContent = text; }
    return e;
  }

  // Has Tucker already offered the tour in this browser tab?
  function offeredAlready() {
    try { return sessionStorage.getItem(OFFERED) === "1"; } catch (e) { return false; }
  }
  // Remember (for this tab only) that the tour was offered, so it doesn't pop up again.
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
    // On small screens the welcome adds a friendly note: everything works, but the site shines on a big screen.
    tipEl = el("p", "tour-tip", "Tip: this site is best experienced on a full-size computer screen. Everything works on " +
                                "your phone, but the side-by-side views are easier to follow on a bigger screen.");
    tipEl.hidden = true;
    var row = el("div", "tour-row");
    countEl = el("span", "tour-count");
    backBtn = el("button", "tour-back", "Back");
    nextBtn = el("button", "tour-next", "Next");
    backBtn.type = nextBtn.type = "button";
    row.appendChild(countEl); row.appendChild(backBtn); row.appendChild(nextBtn);
    body.appendChild(textEl); body.appendChild(tipEl); body.appendChild(row);

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

  // Switch the bubble's guide: Tucker, or Cipher inside his Lair.
  function guide(who) {
    var g = GUIDES[who] || GUIDES.tucker;
    if (picEl.getAttribute("src") !== g.pic) { picEl.src = g.pic; }
    picEl.alt = g.name;
    bubble.classList.toggle("tour-cipher", who === "cipher");
  }

  // The first tour step that happens on the given page.
  function firstOn(page) {
    for (var i = 0; i < STEPS.length; i++) { if (STEPS[i].page === page) { return i; } }
    return 0;
  }

  // Remove the highlight from whatever the guide was pointing at.
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
    toured = true;          // the tour ran on this page, so its follow-up tips are welcome
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
    tipEl.hidden = !(i === 0 && window.matchMedia && window.matchMedia("(max-width: 899px)").matches);
    countEl.textContent = (i + 1) + " of " + STEPS.length;
    backBtn.hidden = i === 0;
    nextBtn.textContent = s.last ? "Done" : s.label || (s.go ? "Take me there" : "Next");
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
    var besideStep = current >= 0 && STEPS[current] && STEPS[current].beside;   // e.g. one column of a two-column layout
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
    if (besideStep && side) {                                      // asked for: bubble beside the item, its top in view
      x = side === "right" ? x0 + r.width + GAP : x0 - w - GAP;
      y = y0;
      scrollTo = y0 - 70;
    } else if (besideStep) {                                       // no room beside (phones): just above it
      x = clampX(x0);
      y = Math.max(EDGE, y0 - h - GAP);
      scrollTo = y - EDGE;
    } else if (r.height + GAP + h + 2 * EDGE <= vh) {             // fits below: center the pair on screen
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
    tipEl.hidden = true;
    guide("tucker");
    textEl.textContent = text;
    countEl.textContent = "";
    backBtn.hidden = true;
    nextBtn.textContent = label;
    bubble.hidden = false;
    place(null);
  }

  // The file name for a tour page ('home' is the site root).
  function pageFile(page) { return page === "home" ? "./" : page + ".html"; }

  // Next button: go to the next step, to the next page, or follow a tip's link.
  function next() {
    var s = STEPS[current];
    if (note) { location.href = note; return; }
    if (s && s.last) { end(); return; }
    if (s && s.go) { location.href = s.go + "?tour=" + (current + 1); return; }
    show(current + 1);
  }

  // Back button: the previous step, on this page or the previous one.
  function back() {
    if (current <= 0) { return; }
    var prev = STEPS[current - 1];
    if (prev.page !== PAGE) { location.href = pageFile(prev.page) + "?tour=" + (current - 1); return; }
    show(current - 1);
  }

  // Close the bubble (the X, Escape or Done).
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

  // Build the bubble, resume a step passed in the address, or offer the tour on a first home-page visit.
  function start() {
    build();
    if (!PAGE) { return; }        // e.g. checkout and the policy pages: just the "Restart the Tour" button
    // After Cipher's attack finishes (cipher.js fires "cipher-done"), Tucker recommends the About Us page.
    if (PAGE === "cipher") {
      document.addEventListener("cipher-done", function () {
        if (!toured) { return; }      // only for visitors taking the tour, not everyone who runs Cipher
        setTimeout(function () {
          tip("Nice work, you survived Cipher! Want to see how all of this is built? The About Us page covers the " +
              "architecture, the AI policies behind me, and the code on GitHub if you really want to dig in.",
              "Show me", "about.html?tour=" + firstOn("about"));
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
