/*
 * cipher.js - Cipher's Lair. One button; then it only SHOWS what the server reports about the run.
 * The visitor sends nothing but the button press (no payloads, no targets). Everything is inserted as text
 * (textContent), never HTML. Polls /api/cipher/status about once a second while a run is in progress.
 */
(function () {
  "use strict";

  var shown = { attacks: 0, soc: 0, actions: 0 }, timer = null, finished = false, introduced = false, analyzing = false;

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

  function setStatus(text) { $("lair-status").textContent = text; }

  function clock(t) { return t ? new Date(t * 1000).toLocaleTimeString([], { hour12: false }) : ""; }

  // ---- the opening: Cipher announces the attack, Tucker answers right away
  function intro(total) {
    if (introduced) { return; }
    introduced = true;
    say("attack", "Muhahaha! I am about to run " + total + " attacks against your little treat shop. " +
                  "Let's see how long your defenses last.");
    line("log-attack", "cipher.announce(attacks = " + total + ")", "big");
    window.setTimeout(function () {
      say("defense", "Incoming! " + total + " attacks headed our way. Tucker's Automated Defenses are kicking in!");
      line("log-defense", "tucker.alert(\"incoming attacks detected\")  => Tucker's Automated Defenses ON", "big");
    }, 700);
  }

  // ---- render one attack: Cipher's box gets the attempt, Tucker's box gets the defense
  function renderAttack(a, n, total) {
    if (a.id === "limit") { line("log-attack", "cipher.halt()  // safety limit reached", "warn"); return; }
    var num = "#" + String(n).padStart(2, "0");
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

  // ---- render one AI SOC check-in
  function renderSoc(c, st) {
    showYou(st && st.visitor);
    if (c.when === "halfway") {
      say("soc", "Hey Tucker, I'm noticing an attack!");
      line("log-soc", "squirrel.checkin(\"halfway\") @ " + clock(c.t), "big");
    } else {
      line("log-soc", "squirrel.checkin(\"final\") @ " + clock(c.t), "big");
    }
    line("log-soc", "headline: " + c.headline);
    (c.lines || []).forEach(function (l) { line("log-soc", "> " + l, "sub"); });
    line("log-soc", "verdict = " + c.verdict + (c.injection_spotted ? "   prompt_injection_spotted = true" : ""),
         c.verdict === "contained" ? "" : "bad");
    if (c.ai === false) { line("log-soc", "(plain-facts mode: the AI was unavailable, so no AI wrote this)", "warn"); }
    if (c.when === "final") { say("soc", c.headline || "Attack contained."); }
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
         " Attacker blocked for 24 hours.", gaps ? "bad" : "big");
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
    var total = st.total || 50;
    (st.attacks || []).slice(shown.attacks).forEach(function (a, i) { renderAttack(a, shown.attacks + i + 1, total); });
    shown.attacks = (st.attacks || []).length;
    (st.soc || []).slice(shown.soc).forEach(function (c) { renderSoc(c, st); });
    shown.soc = (st.soc || []).length;
    (st.actions || []).slice(shown.actions).forEach(renderAction);
    shown.actions = (st.actions || []).length;
    // All attacks are in but the AI's final report isn't back yet: say so, so the box never looks stuck.
    if (st.status === "running" && shown.attacks >= total && shown.soc < 2 && !analyzing) {
      analyzing = true;
      line("log-soc", "squirrel.analyze(\"final\")  // run over: reading all " + total + " attacks and the web logs...", "warn");
      say("soc", "That's all " + total + "! Reading the logs and writing up my final report...");
    }
    if (st.status === "running") {
      setStatus(shown.attacks >= total ? "All " + total + " attacks done. The AI SOC Squirrel is writing its final report..."
                                       : "Attack in progress: " + shown.attacks + " of " + total + "...");
      $("attack").disabled = true; $("attack").textContent = "Attacking...";
    }
    if ((st.status === "done" || st.status === "error") && !finished) { finish(st); }
  }

  function poll() {
    fetch("api/cipher/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (st) {
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
    shown = { attacks: 0, soc: 0, actions: 0 }; finished = false; introduced = false; analyzing = false;
  }

  function start() {
    var btn = $("attack");
    if (finished) { clearBoxes(); }
    btn.disabled = true;                       // the server ignores extra presses too
    btn.textContent = "Attacking...";
    fetch("api/cipher/start", { method: "POST", credentials: "same-origin" })
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
