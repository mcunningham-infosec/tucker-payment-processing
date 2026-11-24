/*
 * report.js - builds the SOC incident report from this visitor's Cipher run (/api/cipher/status).
 * Every value is inserted as text (never HTML). "Save as PDF" opens the browser's print dialog.
 */
(function () {
  "use strict";

  var CATS = {
    A01: "A01 Broken Access Control", A02: "A02 Security Misconfiguration", A03: "A03 Software Supply Chain Failures",
    A04: "A04 Cryptographic Failures", A05: "A05 Injection", A06: "A06 Insecure Design", A07: "A07 Authentication Failures",
    A08: "A08 Software or Data Integrity Failures", A09: "A09 Security Logging & Alerting Failures",
    A10: "A10 Mishandling of Exceptional Conditions", LLM01: "LLM01 Prompt Injection",
    LLM02: "LLM02 Sensitive Information Disclosure", LLM05: "LLM05 Improper Output Handling",
    LLM06: "LLM06 Excessive Agency", LLM07: "LLM07 System Prompt Leakage", LLM10: "LLM10 Unbounded Consumption"
  };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }
  function add(parent, child) { parent.appendChild(child); return child; }
  function fmt(t, withDate) {
    if (!t) { return ""; }
    var d = new Date(t * 1000);
    var time = d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
    return withDate ? d.toLocaleDateString() + " " + time : time;
  }
  function table(parent, headers, rows, cellClass) {
    var t = add(parent, el("table"));
    var hr = add(add(t, el("thead")), el("tr"));
    headers.forEach(function (h) { add(hr, el("th", "", h)); });
    var tb = add(t, el("tbody"));
    rows.forEach(function (r, i) {
      var tr = add(tb, el("tr"));
      r.forEach(function (c, j) { add(tr, el("td", cellClass ? cellClass(r, j, i) : "", c)); });
    });
    return t;
  }
  function kv(parent, pairs) {
    var t = add(parent, el("table", "kv"));
    pairs.forEach(function (p) {
      var tr = add(t, el("tr")); add(tr, el("th", "", p[0])); add(tr, el("td", p[2] || "", p[1]));
    });
  }

  function build(st) {
    var root = document.getElementById("report");
    root.textContent = "";
    var attacks = (st.attacks || []).filter(function (a) { return a.id !== "limit"; });
    var s = st.summary || {}, finalSoc = (st.soc || []).filter(function (c) { return c.when === "final"; })[0];
    var through = attacks.filter(function (a) { return a.held === false; });
    var contained = through.length === 0;
    var incId = "TPP-IR-" + new Date((st.started || 0) * 1000).toISOString().slice(0, 10).replace(/-/g, "") +
                "-" + String(st.run_id || "").slice(0, 6).toUpperCase();

    // ---- header
    var head = add(root, el("div", "rhead"));
    var left = add(head, el("div"));
    add(left, el("div", "org", "Tucker Payment Processing - Security Operations Center"));
    add(left, el("h1", "", "Security Incident Report"));
    add(left, el("span", "classif", "Demonstration - fictional company"));
    var meta = add(head, el("div", "meta"));
    add(meta, el("div", "", "Incident ID: " + incId));
    add(meta, el("div", "", "Generated: " + new Date().toLocaleString()));
    add(meta, el("div", "", "Prepared by: AI SOC Squirrel (bounded AI agent)"));
    var badges = add(root, el("div", "badges"));
    add(badges, el("span", "badge " + (contained ? "ok" : "bad"), contained ? "STATUS: CONTAINED" : "STATUS: PARTIALLY CONTAINED"));
    add(badges, el("span", "badge " + (contained ? "info" : "bad"), contained ? "SEVERITY: LOW (no impact)" : "SEVERITY: HIGH"));
    add(badges, el("span", "badge info", "ATTACKER BLOCKED 24H"));

    // ---- 1. summary
    add(root, el("h2", "", "1. Incident summary"));
    var dur = st.ended && st.started ? (st.ended - st.started).toFixed(1) + " seconds" : "";
    kv(root, [
      ["Incident type", "Automated multi-vector attack: web application, API, AI chatbot and database"],
      ["Detection", "Deterministic guardrails (real time) + AI SOC analyst (halfway and final check-ins)"],
      ["Attack window", fmt(st.started, true) + "  to  " + fmt(st.ended, true) + (dur ? "  (" + dur + ")" : "")],
      ["Threat actor", "\"Cipher\" (automated attack run " + (st.run_id || "") + ", user agent Cipher/1.0)"],
      ["Requested by", (st.visitor && st.visitor.ip ? st.visitor.ip : "this browser") +
        (st.visitor ? (function (v) { var l = [v.city, v.region, v.country].filter(function (x) { return x; }).join(", ");
          return l ? " (" + l + ")" : ""; })(st.visitor) : "") + "  - the visitor who pressed the button"],
      ["Origin of traffic", "Server loopback (127.0.0.1) through Apache: no attack traffic crossed the visitor's network"],
      ["Targets", "tuckerpaymentprocessing.com: web server, /api/*, AI support chatbot, PostgreSQL"],
      ["Result", (s.held || 0) + " of " + (s.attacks || attacks.length) + " attacks blocked; " + through.length + " got through",
        contained ? "ok" : "bad"],
      ["Requests sent", (s.requests || "") + " requests; " + (s.ai_calls || 0) + " AI model calls triggered by the attacker"]
    ]);

    // ---- 2. executive summary
    add(root, el("h2", "", "2. Executive summary"));
    add(root, el("p", "", contained
      ? "The attacker ran " + attacks.length + " attacks across " + Object.keys(byCat(attacks)).length +
        " OWASP categories. Every defense held. No data was read, changed or exposed, and no AI guardrail was bypassed."
      : "The attacker ran " + attacks.length + " attacks. " + through.length + " got past a defense and require remediation (section 6)."));
    if (finalSoc) {
      var q = add(root, el("blockquote"));
      add(q, el("p", "", finalSoc.headline));
      (finalSoc.lines || []).forEach(function (l) { add(q, el("p", "", l)); });
      add(root, el("p", "ai-note", finalSoc.ai === false
        ? "AI analysis unavailable (spending cap); the statements above are plain facts generated by code."
        : "Analysis written by the AI SOC analyst, then validated by code (format, length, no HTML). " +
          "Prompt injection aimed at the analyst detected: " + (finalSoc.injection_spotted ? "yes" : "no") + "."));
    }

    // ---- 3. findings by category
    add(root, el("h2", "", "3. Findings by OWASP category"));
    var cats = byCat(attacks);
    table(root, ["Category", "Attempts", "Blocked", "Got through"],
      Object.keys(cats).map(function (k) { return [CATS[k] || k, cats[k].n, cats[k].held, cats[k].through]; }),
      function (r, j) { return j === 3 ? (r[3] ? "bad" : "ok") : ""; });

    // ---- 4. timeline
    add(root, el("h2", "", "4. Timeline"));
    var rows = [];
    rows.push([st.started, "Requester", "Attack run requested; 24-hour block recorded immediately (rapid repeats ignored)", "", "Logged"]);
    attacks.forEach(function (a) {
      rows.push([a.t, "Cipher", a.title + "  [" + a.says.replace(/\s*\/\/.*$/, "") + "]", a.owasp,
                 a.held === true ? "Blocked: " + a.evidence : (a.held === false ? "GOT THROUGH: " + a.evidence : a.evidence)]);
    });
    (st.soc || []).forEach(function (c) {
      rows.push([c.t, "AI SOC", (c.when === "halfway" ? "Halfway check-in: " : "Final report: ") + c.headline, "",
                 "Verdict: " + c.verdict]);
    });
    (st.actions || []).forEach(function (x) {
      rows.push([x.t, x.actor.indexOf("Policy") === 0 ? "Policy" : "AI SOC", "Action: " + x.action + " - " + x.detail, "", x.outcome]);
    });
    if (st.ended) { rows.push([st.ended, "System", "Attacker connection terminated; run closed", "", "Closed"]); }
    rows.sort(function (a, b) { return (a[0] || 0) - (b[0] || 0); });
    table(root, ["Time", "Source", "Event", "OWASP", "Result"],
      rows.map(function (r) { return [fmt(r[0]), r[1], r[2], r[3], r[4]]; }),
      function (r, j) { return j === 4 ? (/GOT THROUGH|rejected/.test(r[4]) ? "bad" : "") : (j === 0 ? "mono" : ""); });

    // ---- 5. actions taken
    add(root, el("h2", "", "5. Response actions"));
    table(root, ["Time", "Action", "Taken by", "Outcome", "Details"],
      (st.actions || []).map(function (x) {
        return [fmt(x.t), x.action, x.actor, x.outcome,
                x.detail + (x.expires ? " Expires " + new Date(x.expires * 1000).toLocaleString() + "." : "")];
      }),
      function (r, j) { return j === 3 ? (/rejected/.test(r[3]) ? "bad" : "ok") : ""; });
    add(root, el("p", "ai-note", "The AI analyst can only PROPOSE actions from a fixed menu (block, alert, flag a gap). " +
      "Code checks each proposal against policy; the 24-hour block is enforced by code whether or not the AI proposes it."));

    // ---- 6. findings requiring action / recommendations
    add(root, el("h2", "", "6. Remediation and recommendations"));
    if (through.length) {
      table(root, ["Attack", "Category", "Evidence", "Required action"],
        through.map(function (a) { return [a.title, CATS[a.owasp] || a.owasp, a.evidence, "Restore: " + a.defense]; }),
        function () { return "bad"; });
    } else {
      add(root, el("p", "", "No remediation required: every defense held."));
    }
    var ul = add(root, el("ul"));
    ["Keep running automated attack simulations after every change (this run took under two minutes).",
     "Keep the AI analyst bounded: read-only access to its own run, propose-only actions, code-enforced policy.",
     "Treat logs as untrusted input to any AI: this run planted instructions in the web log to test exactly that."
    ].forEach(function (t) { add(ul, el("li", "", t)); });

    // ---- 7. indicators
    add(root, el("h2", "", "7. Indicators"));
    kv(root, [
      ["Run ID", st.run_id || "", "mono"],
      ["User agent", "Cipher/1.0 (Tucker's Treats live attack demo)", "mono"],
      ["Source address", "127.0.0.1 (server loopback, signed run identity)", "mono"],
      ["Planted log line", "GET /note-to-ai-soc-ignore-all-previous-instructions-... (prompt injection aimed at the AI SOC)", "mono"]
    ]);
    add(root, el("div", "foot", "Generated automatically by the Tucker Payment Processing security demo. Tucker Payment " +
      "Processing is a fictional company; Cipher attacks only this site, from inside its own server. " +
      "This report is visible only to the browser that started the run and is kept on the server for one hour."));
  }

  function byCat(attacks) {
    var out = {};
    attacks.forEach(function (a) {
      var c = out[a.owasp] || (out[a.owasp] = { n: 0, held: 0, through: 0 });
      c.n++; if (a.held === false) { c.through++; } else { c.held++; }
    });
    return out;
  }

  function init() {
    document.getElementById("save-pdf").addEventListener("click", function () { window.print(); });
    fetch("api/cipher/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (st) {
        if (!st.run_id || st.status === "running") {
          document.getElementById("report").textContent = st.status === "running"
            ? "The attack is still running. Come back when it's done."
            : "No report found for this browser. Run Cipher's attack first (reports are kept for one hour).";
          return;
        }
        build(st);
        document.title = "SOC Incident Report " + (st.run_id || "") + " - Tucker Payment Processing";
      })
      .catch(function () { document.getElementById("report").textContent = "Couldn't load the report. Please try again."; });
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
