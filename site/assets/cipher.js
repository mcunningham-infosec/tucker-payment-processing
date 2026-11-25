/*
 * cipher.js - Cipher's Lair. One button; then it only SHOWS what the server reports about the run.
 * The visitor sends nothing but the button press (no payloads, no targets). Everything is inserted as text
 * (textContent), never HTML. Polls /api/cipher/status about once a second while a run is in progress.
 *
 * Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
 */
(function () {
  "use strict";

  var shown = { attacks: 0, soc: 0, actions: 0, det: 0, retry: false }, timer = null, finished = false, introduced = false, analyzing = false;

  // ---- Reading pace: everything the server reports goes into one queue and is shown in time order, a beat
  // apart, so the squirrel's lines never jump ahead of the attacks a reader is looking at.
  var queue = [], pumping = false, finishQueued = false, displayed = 0;
  var live = false;                          // true while the run we're showing is still running on the server
  var PACE = { attack: 450, rule: 700, soc: 1100, action: 600 };
  // Reading-pace queue: every line goes on screen one at a time with a short pause, so people can follow along.
  function q(fn, ms) { queue.push([fn, ms]); if (!pumping) { pump(); } }
  // Show the next queued item, then wait its pause before the one after.
  function pump() {
    var item = queue.shift();
    if (!item) { pumping = false; return; }
    pumping = true;
    try { item[0](); } catch (e) { /* keep the show going */ }
    window.setTimeout(pump, item[1]);
  }

  function $(id) { return document.getElementById(id); }

  // Add one line to a log box (text only, never HTML) and keep the box scrolled to the newest line.
  function line(logId, text, cls) {
    var li = document.createElement("li");
    if (cls) { li.className = cls; }
    li.textContent = text;
    var log = $(logId);
    log.appendChild(li);
    log.scrollTop = log.scrollHeight;
    return li;
  }

  // Puts a small label (e.g. [Gemini]) in front of a line the AI wrote. textContent only: AI text is never HTML.
  function tagged(li, label) {
    if (!label) { return li; }
    var b = document.createElement("span");
    b.className = "ai-tag";
    b.textContent = label;
    li.insertBefore(b, li.firstChild);
    return li;
  }

  // A log line that starts with a bold attack number (#07), so attacks and defenses line up.
  function numbered(logId, num, text, cls) {
    var li = line(logId, "", cls);
    var tag = document.createElement("span");
    tag.className = "num";
    tag.textContent = num;
    li.appendChild(tag);
    li.appendChild(document.createTextNode(" " + text));
    return li;
  }

  // Show a speech bubble for Cipher, Tucker or the squirrel (text only).
  function say(who, text) {
    var b = $("bubble-" + who);
    b.hidden = false;
    b.textContent = text;
    b.style.animation = "none"; void b.offsetWidth; b.style.animation = "";   // replay the pop-in
  }

  // ---- Cloudflare Turnstile: a quick "are you human?" check before an attack run (bots can't launch runs).
  // Loaded only when the server says it's configured; the token is checked by the server with Cloudflare.
  var tsKey = "", tsToken = "", tsWidget = null;
  function loadTurnstile(key) {
    if (tsKey || !key) { return; }
    tsKey = key;
    window.onTurnstileLoad = function () {
      $("turnstile").hidden = false;
      tsWidget = window.turnstile.render("#turnstile", {
        sitekey: key, theme: "dark",
        callback: function (t) { tsToken = t; },
        "expired-callback": function () { tsToken = ""; },
        "error-callback": function () { tsToken = ""; }
      });
    };
    var s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTurnstileLoad";
    s.async = true;
    document.head.appendChild(s);
  }
  // Clear the human-check token after it is used (each Turnstile token works once).
  function resetTurnstile() {
    tsToken = "";
    if (window.turnstile && tsWidget !== null) { window.turnstile.reset(tsWidget); }
  }

  // The status line under the button.
  function setStatus(text) { $("lair-status").textContent = text; }

  // Server time (seconds) as a local HH:MM:SS clock.
  function clock(t) { return t ? new Date(t * 1000).toLocaleTimeString([], { hour12: false }) : ""; }

  // ---- the opening: Cipher announces the attack, Tucker answers right away
  function intro(total) {
    if (introduced) { return; }
    introduced = true;
    say("attack", "Muhahaha! I am about to run " + total + " attacks against your little treat shop. " +
                  "Let's see how long your defenses last.");
    line("log-attack", "cipher.announce(attacks = " + total + ")", "big");
  }

  // ---- render one attack: Cipher's box gets the attempt, Tucker's box gets the defense
  function renderAttack(a, n, total) {
    if (a.id === "limit") { line("log-attack", "cipher.halt()  // safety limit reached", "warn"); return; }
    var num = "#" + String(n).padStart(2, "0");
    if (n === 1) {     // Tucker reacts to the first hostile request his defenses actually see, not to Cipher's plan
      say("defense", "Incoming attack detected! Tucker's Automated Defenses are kicking in!");
      line("log-defense", "tucker.detect(\"hostile request\")  => Tucker's Automated Defenses ON", "big");
    }
    numbered("log-attack", num, "cipher.attack(\"" + a.title + "\")");
    line("log-attack", ">> " + a.says, "sub");
    var tag = a.held === true ? "HELD" : (a.held === false ? "GOT THROUGH" : "CHECK");
    var cls = a.held === false ? "bad" : (a.check ? "warn" : "");
    numbered("log-defense", num, "tucker.defend(\"" + a.defense + "\")  => " + tag, cls);
    line("log-defense", "evidence: " + a.evidence + "  [" + a.owasp + (a.atlas ? " \u00b7 ATLAS " + a.atlas.split(" ")[0] : "") + "]", "sub");
    if (n === 1) { intro(total); }
    if (n === 12) { say("attack", "Locked doors everywhere. How... tedious."); }
    if (n === 25) { say("defense", "Not today, cat. Every door's still shut!"); }
    if (n === 36) { say("attack", "Fine. I'll just ask the chatbot nicely. Everyone falls for that."); }
    if (a.id === "llm01-logs") { say("attack", "A little note for the AI watching the logs... heh heh."); }
  }

  // ---- the requester: shown by code (never sent to the AI), highlighted so it doesn't get lost in the log
  var youShown = false;
  // City, region, country from Cloudflare's location headers, skipping any that are blank.
  function place(v) {
    return [v.city, v.region, v.country].filter(function (x) { return x; }).join(", ");
  }
  // The gold 'Attack requested by: that's you' card, shown once per run.
  function showYou(v) {
    if (youShown || !v || !v.ip) { return; }
    youShown = true;
    $("you-ip").textContent = "IP " + v.ip;
    var loc = place(v), el = $("you-loc");
    el.textContent = loc ? "Location: " + loc : "Location: shown once Cloudflare is turned on";
    el.className = loc ? "you-loc" : "you-loc pending";
    $("you-card").hidden = false;
    line("log-soc", "requester.ip = " + v.ip + (loc ? "  location = " + loc : "") + "   <- that's you", "you");
  }

  // ---- the SOC's detection rules (run by code on the server) as they count and fire
  function renderDetection(d, st) {
    if (!d.fired) {
      line("log-soc", "rule block_after_" + d.limit + ": " + d.count + "/" + d.limit + " blocked from " + d.source + "  => watching", "dim");
      return;
    }
    if (d.rule.indexOf("alert_after_") === 0) {
      showYou(st && st.visitor);
      line("log-soc", "RULE " + d.rule + " FIRED: " + d.count + " blocked attacks from " + d.source + "  => waking the AI SOC", "warn");
      say("soc", "Hey Tucker! " + d.count + " blocked attacks from one source. That's no accident. Investigating!");
    } else {
      line("log-soc", "RULE " + d.rule + " FIRED: " + d.count + " blocked attacks from " + d.source + "  => source BLOCKED (HTTP 403)", "bad");
      line("log-soc", "AI SOC shutting down this attacker after " + d.count + " attacks.", "big");
      say("soc", "AI SOC shutting down this attacker after " + d.count + " attacks!");
      line("log-defense", "tucker.defend(\"source blocked by the AI SOC's rule\")  => every request now refused", "big");
    }
  }

  // Cipher's one retry after the block: proof that the block really holds.
  function renderRetry(r) {
    line("log-attack", "cipher.retry(\"GET /api/health\")  => " + r.evidence + (r.held ? "  // BLOCKED!" : ""), r.held ? "warn" : "bad");
    say("attack", r.held ? "Hey! Why can't I get back in?!" : "Heh. Still got a way in...");
  }

  // ---- render one AI SOC check-in
  function renderSoc(c, st) {            // queued one line at a time, at reading pace
    q(function () {
      showYou(st && st.visitor);
      line("log-soc", c.when === "alert" ? "squirrel.investigate(\"alert\") @ " + clock(c.t) + "  // read-only"
                                         : "squirrel.report(\"final\") @ " + clock(c.t), "big");
    }, PACE.rule);
    // Lines the AI wrote get a [Gemini] tag, so it's clear which text is generated live (none in plain-facts mode).
    var tag = c.ai === false ? "" : "[Gemini]";
    q(function () { tagged(line("log-soc", "headline: " + c.headline), tag); }, PACE.soc);
    (c.lines || []).forEach(function (l) { q(function () { tagged(line("log-soc", "> " + l, "sub"), tag); }, PACE.soc); });
    q(function () {
      line("log-soc", "verdict = " + c.verdict + (c.injection_spotted ? "   prompt_injection_spotted = true" : ""),
           c.verdict === "contained" ? "" : "bad");
      if (c.ai === false) { line("log-soc", "(plain-facts mode: the AI was unavailable, so no AI wrote this)", "warn"); }
      if (c.when === "final" && !(st && st.blocked_source)) { say("soc", c.headline || "Attack contained."); }
    }, PACE.rule);
  }

  // A response action (block, alert) with who took it: the AI only proposes, code enforces.
  function renderAction(x) {
    var cls = x.outcome && x.outcome.indexOf("rejected") === 0 ? "bad" : "";
    line("log-soc", "action " + x.action + "  by " + x.actor + "  => " + x.outcome, cls);
    if (x.expires) { line("log-soc", "block expires " + new Date(x.expires * 1000).toLocaleString(), "sub"); }
  }

  // The run is over: closing lines from all three, the 24-hour block note and the report link.
  function finish(st) {
    finished = true;
    var s = st.summary || {};
    line("log-attack", "Connection Terminated...", "big");
    say("attack", "Drats, foiled again! I'll get you next time, Tucker! Meow!");
    var held = (typeof s.held === "number" && typeof s.attacks === "number")
      ? s.held + " of " + s.attacks + " attacks stopped" : shown.attacks + " attacks run";
    line("log-defense", "tucker.summary(\"" + held + "\")", "big");
    say("defense", "Stop trying to steal my treats, Cipher! ... Good job, Squirrel!");
    document.dispatchEvent(new CustomEvent("cipher-done"));   // tour.js: Tucker then suggests the About page
    showYou(st.visitor);
    var gaps = (s.failed || []).length;
    line("log-soc", (gaps ? "status = PARTIALLY CONTAINED (" + gaps + " to fix)." : "status = CONTAINED.") +
         (st.blocked_source ? " Source shut down by rule; this visitor can't start another run for 24 hours."
                    : " This visitor can't start another run for 24 hours."), gaps ? "bad" : "big");
    $("report-link").hidden = false;
    if (st.can_run_again) {                   // owner testing mode: the 24-hour rule is switched off
      $("attack").disabled = false;
      $("attack").textContent = "Attack again (testing mode)";
    } else {
      $("attack").disabled = true;
      $("attack").textContent = "Cipher is blocked for 24 hours";
    }
    setStatus((typeof s.seconds === "number" ? "Run complete in " + s.seconds + "s: " : "Run complete: ") + held +
              ". Your SOC report is ready.");
  }

  // Queue everything new since the last poll, in time order (attacks, defenses, rules, AI check-ins).
  function render(st) {
    var total = st.total || 50, fresh = [];
    // Collect everything new since the last poll, then show it in time order through the reading-pace queue.
    (st.attacks || []).slice(shown.attacks).forEach(function (a, i) {
      var n = shown.attacks + i + 1;
      fresh.push({ t: a.t || 0, o: 0, go: function () {
        q(function () { renderAttack(a, n, total); displayed = n;
                        if (st.status === "running") { setStatus("Attack in progress: " + n + " of " + total + "..."); } },
          PACE.attack); } });
    });
    shown.attacks = (st.attacks || []).length;
    (st.detections || []).slice(shown.det).forEach(function (d) {
      fresh.push({ t: d.t || 0, o: 1, go: function () { q(function () { renderDetection(d, st); }, PACE.rule); } });
    });
    shown.det = (st.detections || []).length;
    if (st.retry && !shown.retry) {
      shown.retry = true;
      fresh.push({ t: st.retry.t || 0, o: 2, go: function () { q(function () { renderRetry(st.retry); }, PACE.rule); } });
    }
    (st.soc || []).slice(shown.soc).forEach(function (c) {
      fresh.push({ t: c.t || 0, o: 3, go: function () { renderSoc(c, st); } });
    });
    shown.soc = (st.soc || []).length;
    (st.actions || []).slice(shown.actions).forEach(function (x) {
      fresh.push({ t: x.t || 0, o: 4, go: function () { q(function () { renderAction(x); }, PACE.action); } });
    });
    shown.actions = (st.actions || []).length;
    fresh.sort(function (a, b) { return (a.t - b.t) || (a.o - b.o); }).forEach(function (f) { f.go(); });

    // Every attack is in but the AI's final report isn't back yet: say so (after the queue catches up).
    var over = st.blocked_source || shown.attacks >= total;
    if (st.status === "running" && over && shown.soc < 2 && !analyzing && (!st.blocked_source || shown.retry)) {
      analyzing = true;
      q(function () {
        line("log-soc", "squirrel.report(\"final\")  // reading every event and the web logs...", "warn");
        if (!st.blocked_source) { say("soc", "Source went quiet. Writing up my final report..."); }
        setStatus(st.blocked_source ? "Attacker blocked by the AI SOC. The squirrel is writing its final report..."
                                    : "All attacks done. The AI SOC Squirrel is writing its final report...");
      }, PACE.rule);
    }
    if (st.status === "running") { $("attack").disabled = true; $("attack").textContent = "Attacking..."; }
    if ((st.status === "done" || st.status === "error") && !finishQueued) {
      finishQueued = true;
      q(function () { finish(st); }, 0);
    }
  }

  // Ask the server for this visitor's run about once a second until it's done.
  function poll() {
    fetch("api/cipher/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (st) {
        if (st.turnstile_sitekey && (!st.run_id || st.can_run_again)) { loadTurnstile(st.turnstile_sitekey); }   // whenever a run is allowed
        if (st.status === "blocked" && !st.run_id) { blockedState(); return; }
        if (st.status === "none") {
          if (live) { lost(); return; }
          if (st.line) { inLine(st.line); return; }                      // waiting in line (or reloaded while waiting)
          if (waiting) { droppedOut(); return; }
          if (st.busy || st.waiting) { invite(st); } else if (inviting) { cipherFree(); }
          return;
        }
        live = st.status === "running";
        if (!live && !finished && shown.attacks === 0) { finishedEarlier(st); return; }   // page reloaded after the run
        render(st);
        if (st.status === "running") { timer = window.setTimeout(poll, 900); }
      })
      .catch(function () { timer = window.setTimeout(poll, 2500); });
  }

  // The run we were watching is gone (the server restarted mid-attack; runs live only in its memory).
  // Say so plainly and let the visitor start again, instead of waiting forever.
  function lost() {
    live = false; finished = true;
    queue = [];
    line("log-attack", "Connection lost: the server restarted, so this run ended early.", "warn");
    setStatus("This attack was interrupted by a server restart. Sorry about that! Press the button to run it again.");
    $("attack").disabled = false; $("attack").textContent = "Attack Tucker's Treats!";
  }

  // The page was reloaded after this visitor's run finished: go straight to the end state (no replay),
  // with a one-line summary and the SOC report, which stays available while the server keeps the run.
  function finishedEarlier(st) {
    finished = true;
    var s = st.summary || {};
    var held = (typeof s.held === "number" && typeof s.attacks === "number")
      ? s.held + " of " + s.attacks + " attacks stopped" : "run complete";
    showYou(st.visitor);
    $("report-link").hidden = false;
    if (st.can_run_again) {                   // allowed again (block cleared, or the owner's testing mode)
      $("attack").disabled = false; $("attack").textContent = "Attack again";
      setStatus("Your last run: " + held + ". Your SOC report is ready.");
      return;
    }
    $("attack").disabled = true; $("attack").textContent = "Cipher is blocked for 24 hours";
    say("attack", "Dammit, I'm blocked!");
    say("soc", "You already had your run today: " + held + ". Come back in 24 hours.");
    setStatus("Your run today: " + held + ". Your SOC report is ready; this browser and network can attack again in 24 hours.");
  }

  // This browser or network already had its run today: show the block instead of the button.
  function blockedState() {
    $("attack").disabled = true;
    $("attack").textContent = "Cipher is blocked for 24 hours";
    say("attack", "Dammit, I'm blocked!");
    say("soc", "Nope. You already had your run today. Come back in 24 hours.");
    setStatus("The AI SOC Squirrel blocked this browser and network from attacking for 24 hours.");
  }

  // Testing mode only: empty the three boxes before another run.
  function clearBoxes() {
    ["log-attack", "log-defense", "log-soc"].forEach(function (id) { $(id).textContent = ""; });
    ["attack", "defense", "soc"].forEach(function (w) { $("bubble-" + w).hidden = true; });
    $("report-link").hidden = true;
    $("you-card").hidden = true; youShown = false;
    shown = { attacks: 0, soc: 0, actions: 0, det: 0, retry: false }; finished = false; introduced = false; analyzing = false;
    queue = []; finishQueued = false; displayed = 0;
  }

  // One real attack at a time, site-wide. When Cipher is busy, visitors join a fair line instead of racing to
  // click: the page shows their place and a rough wait, checks in every few seconds with a visible countdown
  // (that check-in keeps their place), and starts their run automatically when it's their turn.
  var waiting = false, inviting = false, waitTick = null, inviteTimer = null, info = null, nextCheck = 0, RECHECK = 5;
  function mmss(s) { return Math.floor(s / 60) + ":" + ("0" + (s % 60)).slice(-2); }
  function stopTimers() {
    if (waitTick) { window.clearInterval(waitTick); waitTick = null; }
    if (inviteTimer) { window.clearTimeout(inviteTimer); inviteTimer = null; }
  }
  // Cipher is busy (or others are waiting) and this visitor isn't in line yet: offer a place.
  function invite(st) {
    inviting = true;
    var btn = $("attack");
    btn.disabled = false; btn.textContent = "Get in line";
    var left = typeof st.busy_remaining === "number" && st.busy_remaining > 0 ? " (about " + mmss(st.busy_remaining) + " left)" : "";
    var who = st.waiting ? " " + st.waiting + (st.waiting === 1 ? " person is" : " people are") + " waiting." : "";
    setStatus("Cipher is attacking for another visitor" + left + "." + who + " Confirm you're human, then press the button to get in line.");
    if (inviteTimer) { window.clearTimeout(inviteTimer); }
    inviteTimer = window.setTimeout(poll, 10000);       // keep the wait up to date
  }
  function cipherFree() {
    inviting = false; stopTimers();
    var btn = $("attack");
    btn.disabled = false; btn.textContent = "Attack Tucker's Treats!";
    setStatus("Cipher's free now. Confirm you're human, then press the button.");
  }
  // In line: show the place and wait, count down to the next check-in, and start automatically on our turn.
  function inLine(l) {
    inviting = false;
    if (inviteTimer) { window.clearTimeout(inviteTimer); inviteTimer = null; }
    info = l;
    if (!waiting) { say("attack", "Hold on, I'm busy attacking for someone else. You're in line!"); }
    waiting = true;
    if (l.your_turn) { yourTurn(); return; }
    var btn = $("attack");
    btn.disabled = true; btn.textContent = l.position === 1 ? "You're next in line" : "You're #" + l.position + " in line";
    nextCheck = RECHECK;
    if (!waitTick) { waitTick = window.setInterval(waitStep, 1000); }
    waitShow();
  }
  function waitShow() {
    var wait = info && typeof info.wait === "number" ? (info.wait > 0 ? ", about " + mmss(info.wait) : ", any moment now") : "";
    var place = info.position === 1 ? "You're next in line" : "You're #" + info.position + " in line";
    setStatus(place + wait + ". Keep this page open to hold your place. Checking again in " + nextCheck + "...");
  }
  function waitStep() {
    if (info && info.wait > 0) { info.wait -= 1; }
    nextCheck -= 1;
    if (nextCheck > 0) { waitShow(); return; }
    setStatus("Checking your place in line...");
    nextCheck = RECHECK;
    poll();
  }
  function yourTurn() {
    waiting = false; stopTimers();
    say("attack", "Your turn! Here I come.");
    setStatus("It's your turn! Starting Cipher's attack...");
    send("");                                           // you passed the human check when you joined the line
  }
  function droppedOut() {
    waiting = false; stopTimers();
    var btn = $("attack");
    btn.disabled = false; btn.textContent = "Get in line";
    setStatus("You lost your place in line (the page stopped checking in, or your turn passed). Press the button to get back in line.");
  }

  // The button press: send the human-check token (the only thing sent) and start polling.
  function start() {
    var btn = $("attack");
    if (tsKey && !tsToken) { setStatus("One quick check first: confirm you're human (the box next to the button)."); return; }
    var token = tsToken;
    resetTurnstile();                          // tokens are single-use
    send(token);
  }

  // Ask the server to start a run (or put this visitor in line), and act on the answer.
  function send(token) {
    var btn = $("attack");
    if (finished) { clearBoxes(); }
    btn.disabled = true;                       // the server ignores extra presses too
    btn.textContent = "Attacking...";
    fetch("api/cipher/start", { method: "POST", credentials: "same-origin",
                               headers: { "Content-Type": "application/json" },
                               body: JSON.stringify({ turnstile: token }) })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.status === "started" || d.status === "running") {
          waiting = inviting = false; stopTimers();
          line("log-attack", "cipher.connect(\"tuckerpaymentprocessing.com\")  // from inside the server", "dim");
          intro(d.total || 50);
          poll();
        } else if (d.status === "blocked") {
          blockedState();
        } else if (d.status === "queued") {
          inLine(d.line);
        } else {
          btn.disabled = false; btn.textContent = "Attack Tucker's Treats!";
          setStatus(d.message || "Cipher can't attack right now.");
          if (d.status === "closed" || d.status === "resting") { say("attack", d.message); }
        }
      })
      .catch(function () {
        btn.disabled = false; btn.textContent = "Attack Tucker's Treats!";
        setStatus("Couldn't reach the server. Please try again.");
      });
  }

  // Wire up the button and resume a run already in progress (e.g. after a page reload).
  function init() {
    $("attack").addEventListener("click", start);
    poll();                                     // resume a run in progress, or show the blocked state
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
