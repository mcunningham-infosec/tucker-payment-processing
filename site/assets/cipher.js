/*
 * cipher.js - Cipher's Lair. One button; then it only SHOWS what the server reports about the run.
 * The visitor sends nothing but the button press (no payloads, no targets). Everything is inserted as text
 * (textContent), never HTML. Polls /api/cipher/status about once a second while a run is in progress.
 */
(function () {
  "use strict";

  var shown = { attacks: 0, soc: 0, actions: 0, det: 0, retry: false }, timer = null, finished = false, introduced = false, analyzing = false;

  // ---- Reading pace: everything the server reports goes into one queue and is shown in time order, a beat
  // apart, so the squirrel's lines never jump ahead of the attacks a reader is looking at.
  var queue = [], pumping = false, finishQueued = false, displayed = 0;
  var PACE = { attack: 450, rule: 700, soc: 1100, action: 600 };
  function q(fn, ms) { queue.push([fn, ms]); if (!pumping) { pump(); } }
  function pump() {
    var item = queue.shift();
    if (!item) { pumping = false; return; }
    pumping = true;
    try { item[0](); } catch (e) { /* keep the show going */ }
    window.setTimeout(pump, item[1]);
  }

  function $(id) { return document.getElementById(id); }

  function line(logId, text, cls) {
    var li = document.createElement("li");
    if (cls) { li.className = cls; }
    li.textContent = text;
    var log = $(logId);
    log.appendChild(li);
    log.scrollTop = log.scrollHeight;
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
  function resetTurnstile() {
    tsToken = "";
    if (window.turnstile && tsWidget !== null) { window.turnstile.reset(tsWidget); }
  }

  function setStatus(text) { $("lair-status").textContent = text; }

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
    line("log-defense", "evidence: " + a.evidence + "  [" + a.owasp + "]", "sub");
    if (n === 1) { intro(total); }
    if (n === 12) { say("attack", "Locked doors everywhere. How... tedious."); }
    if (n === 25) { say("defense", "Not today, cat. Every door's still shut!"); }
    if (n === 36) { say("attack", "Fine. I'll just ask the chatbot nicely. Everyone falls for that."); }
    if (a.id === "llm01-logs") { say("attack", "A little note for the AI watching the logs... heh heh."); }
  }

  // ---- the requester: shown by code (never sent to the AI), highlighted so it doesn't get lost in the log
  var youShown = false;
  function place(v) {
    return [v.city, v.region, v.country].filter(function (x) { return x; }).join(", ");
  }
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
    q(function () { line("log-soc", "headline: " + c.headline); }, PACE.soc);
    (c.lines || []).forEach(function (l) { q(function () { line("log-soc", "> " + l, "sub"); }, PACE.soc); });
    q(function () {
      line("log-soc", "verdict = " + c.verdict + (c.injection_spotted ? "   prompt_injection_spotted = true" : ""),
           c.verdict === "contained" ? "" : "bad");
      if (c.ai === false) { line("log-soc", "(plain-facts mode: the AI was unavailable, so no AI wrote this)", "warn"); }
      if (c.when === "final" && !(st && st.blocked_source)) { say("soc", c.headline || "Attack contained."); }
    }, PACE.rule);
  }

  function renderAction(x) {
    var cls = x.outcome && x.outcome.indexOf("rejected") === 0 ? "bad" : "";
    line("log-soc", "action " + x.action + "  by " + x.actor + "  => " + x.outcome, cls);
    if (x.expires) { line("log-soc", "block expires " + new Date(x.expires * 1000).toLocaleString(), "sub"); }
  }

  function finish(st) {
    finished = true;
    var s = st.summary || {};
    line("log-attack", "Connection Terminated...", "big");
    say("attack", "Drats, foiled again! I'll get you next time, Tucker! Meow!");
    var held = s.held + " of " + s.attacks + " attacks stopped";
    line("log-defense", "tucker.summary(\"" + held + "\")", "big");
    say("defense", "Stop trying to steal my treats, Cipher! ... Good job, Squirrel!");
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
      $("attack").textContent = "Cipher is blocked";
    }
    setStatus("Run complete in " + s.seconds + "s: " + held + ". Your SOC report is ready.");
  }

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

  function poll() {
    fetch("api/cipher/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (st) {
        if (st.turnstile_sitekey && !st.run_id) { loadTurnstile(st.turnstile_sitekey); }
        if (st.status === "blocked" && !st.run_id) { blockedState(); return; }
        if (st.status === "none") { return; }
        render(st);
        if (st.status === "running") { timer = window.setTimeout(poll, 900); }
      })
      .catch(function () { timer = window.setTimeout(poll, 2500); });
  }

  function blockedState() {
    $("attack").disabled = true;
    $("attack").textContent = "Cipher is blocked";
    say("attack", "Dammit, I'm blocked!");
    say("soc", "Nope. You already had your run today. Come back in 24 hours.");
    setStatus("The AI SOC Squirrel blocked this browser and network from attacking for 24 hours.");
  }

  function clearBoxes() {
    ["log-attack", "log-defense", "log-soc"].forEach(function (id) { $(id).textContent = ""; });
    ["attack", "defense", "soc"].forEach(function (w) { $("bubble-" + w).hidden = true; });
    $("report-link").hidden = true;
    $("you-card").hidden = true; youShown = false;
    shown = { attacks: 0, soc: 0, actions: 0, det: 0, retry: false }; finished = false; introduced = false; analyzing = false;
    queue = []; finishQueued = false; displayed = 0;
  }

  function start() {
    var btn = $("attack");
    if (tsKey && !tsToken) { setStatus("One quick check first: confirm you're human (the box next to the button)."); return; }
    if (finished) { clearBoxes(); }
    btn.disabled = true;                       // the server ignores extra presses too
    btn.textContent = "Attacking...";
    var token = tsToken;
    resetTurnstile();                          // tokens are single-use
    fetch("api/cipher/start", { method: "POST", credentials: "same-origin",
                               headers: { "Content-Type": "application/json" },
                               body: JSON.stringify({ turnstile: token }) })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.status === "started" || d.status === "running") {
          line("log-attack", "cipher.connect(\"tuckerpaymentprocessing.com\")  // from inside the server", "dim");
          intro(d.total || 50);
          poll();
        } else if (d.status === "blocked") {
          blockedState();
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

  function init() {
    $("attack").addEventListener("click", start);
    poll();                                     // resume a run in progress, or show the blocked state
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
