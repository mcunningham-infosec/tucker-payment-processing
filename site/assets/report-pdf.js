/*
 * report-pdf.js - "Download PDF" for the SOC incident report.
 *
 * Builds a real PDF file in the visitor's browser from the report already on the page (built by report.js from
 * this visitor's own run), so the PDF always matches what's on screen. Nothing is sent anywhere.
 *
 * The PDF library (pdfmake, MIT license) is self-hosted in assets/vendor/ - no third-party scripts, in line with
 * the site's Content-Security-Policy - and is only loaded when the button is pressed. If anything goes wrong,
 * it falls back to the browser's own print-to-PDF.
 */
(function () {
  "use strict";

  var VENDOR = ["assets/vendor/pdfmake.min.js", "assets/vendor/vfs_fonts.js"];
  var C = { ink: "#1b1f24", muted: "#5b6470", line: "#d7dce2", brand: "#1f5fbf", ok: "#1e7d46", bad: "#b3261e",
            warn: "#9a6700", head: "#f3f5f8", banner: "#eef5ff", quote: "#f6f9ff", info: "#4b5563" };

  function txt(node) { return (node.textContent || "").replace(/\s+/g, " ").trim(); }

  // Load the PDF library on first use (one script after the other: the fonts file needs pdfmake first).
  function loadLibrary() {
    if (window.pdfMake && window.pdfMake.vfs) { return Promise.resolve(); }
    return VENDOR.reduce(function (p, src) {
      return p.then(function () {
        return new Promise(function (ok, fail) {
          var s = document.createElement("script");
          s.src = src + "?v=0.2.23";
          s.onload = ok;
          s.onerror = function () { fail(new Error("could not load " + src)); };
          document.head.appendChild(s);
        });
      });
    }, Promise.resolve());
  }

  // ---- turn each part of the on-screen report into pdfmake content --------------------------------------------

  function cellStyle(td) {
    var st = { text: txt(td) };
    if (td.classList.contains("bad")) { st.color = C.bad; st.bold = true; }
    else if (td.classList.contains("ok")) { st.color = C.ok; st.bold = true; }
    else if (td.classList.contains("warn")) { st.color = C.warn; st.bold = true; }
    if (td.classList.contains("mono")) { st.fontSize = 7.5; }
    return st;
  }

  function lineTable() {   // thin horizontal rules between rows, like the page
    return { hLineWidth: function (i) { return i === 0 ? 0 : 0.5; }, vLineWidth: function () { return 0; },
             hLineColor: function () { return C.line; }, paddingLeft: function () { return 4; },
             paddingRight: function () { return 4; }, paddingTop: function () { return 3; }, paddingBottom: function () { return 3; } };
  }

  function kvTable(t) {
    var body = [].map.call(t.querySelectorAll("tr"), function (tr) {
      var th = tr.querySelector("th"), td = tr.querySelector("td");
      return [{ text: th ? txt(th) : "", color: C.muted, bold: true }, td ? cellStyle(td) : ""];
    });
    return { table: { widths: [120, "*"], body: body }, layout: lineTable(), margin: [0, 2, 0, 6] };
  }

  function dataTable(t) {
    var heads = [].map.call(t.querySelectorAll("thead th"), function (th) { return { text: txt(th), bold: true, fillColor: C.head }; });
    var rows = [].map.call(t.querySelectorAll("tbody tr"), function (tr) { return [].map.call(tr.children, cellStyle); });
    // Long-text columns share the spare width; short ones (times, counts) size to fit.
    var widths = heads.map(function (h, j) {
      var total = rows.reduce(function (n, r) { return n + ((r[j] && r[j].text) || "").length; }, 0);
      return rows.length && total / rows.length > 22 ? "*" : "auto";
    });
    return { table: { headerRows: 1, widths: widths, body: [heads].concat(rows), dontBreakRows: true },
             layout: lineTable(), fontSize: 8, margin: [0, 2, 0, 6] };
  }

  function boxed(content, fill, edge) {   // a filled box with a colored left edge (banner, quote)
    return { table: { widths: ["*"], body: [[content]] }, margin: [0, 4, 0, 6],
             layout: { fillColor: function () { return fill; }, hLineWidth: function () { return 0; },
                       vLineWidth: function (i) { return i === 0 ? 3 : 0; }, vLineColor: function () { return edge; },
                       paddingLeft: function () { return 8; }, paddingRight: function () { return 8; },
                       paddingTop: function () { return 6; }, paddingBottom: function () { return 6; } } };
  }

  function header(h) {
    var left = h.children[0], meta = h.querySelector(".meta");
    var org = left.querySelector(".org"), title = left.querySelector("h1"), classif = left.querySelector(".classif");
    return [
      { columns: [
          { width: "*", stack: [
              { text: org ? txt(org) : "", color: C.brand, bold: true, fontSize: 9 },
              { text: title ? txt(title) : "", bold: true, fontSize: 18, margin: [0, 2, 0, 2] },
              { text: classif ? txt(classif).toUpperCase() : "", color: C.warn, bold: true, fontSize: 7 } ] },
          { width: 230, alignment: "right", fontSize: 8, color: C.muted,
            stack: meta ? [].map.call(meta.children, function (d) { return { text: txt(d) }; }) : [] } ] },
      { canvas: [{ type: "line", x1: 0, y1: 4, x2: 532, y2: 4, lineWidth: 2, lineColor: C.brand }], margin: [0, 0, 0, 6] }
    ];
  }

  function badges(b) {
    var cells = [].map.call(b.querySelectorAll(".badge"), function (s) {
      var fill = s.classList.contains("ok") ? C.ok : s.classList.contains("bad") ? C.bad : C.info;
      return { text: txt(s), color: "#ffffff", bold: true, fontSize: 8, fillColor: fill, margin: [4, 1, 4, 1] };
    });
    if (!cells.length) { return null; }
    return { table: { widths: cells.map(function () { return "auto"; }), body: [cells] }, margin: [0, 2, 0, 4],
             layout: { hLineWidth: function () { return 2; }, vLineWidth: function () { return 4; },
                       hLineColor: function () { return "#ffffff"; }, vLineColor: function () { return "#ffffff"; } } };
  }

  function convert(root) {
    var out = [];
    [].forEach.call(root.children, function (n) {
      var tag = n.tagName, cls = n.classList;
      if (cls.contains("rhead")) { out.push.apply(out, header(n)); }
      else if (cls.contains("live-banner")) {
        out.push(boxed({ text: [].map.call(n.childNodes, function (c) {
          return { text: c.textContent, bold: c.tagName === "STRONG", color: c.tagName === "STRONG" ? C.brand : C.ink };
        }), fontSize: 8.5 }, C.banner, C.brand));
      }
      else if (cls.contains("badges")) { var b = badges(n); if (b) { out.push(b); } }
      else if (tag === "H2") {
        out.push({ text: txt(n).toUpperCase(), color: C.brand, bold: true, fontSize: 10.5, margin: [0, 12, 0, 1], headlineLevel: 1 });
        out.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 532, y2: 0, lineWidth: 0.5, lineColor: C.line }], margin: [0, 0, 0, 4] });
      }
      else if (tag === "TABLE") { out.push(cls.contains("kv") ? kvTable(n) : dataTable(n)); }
      else if (tag === "BLOCKQUOTE") {
        out.push(boxed({ stack: [].map.call(n.querySelectorAll("p"), function (p, i) {
          return { text: txt(p), bold: i === 0, margin: [0, 1, 0, 1] };
        }) }, C.quote, C.brand));
      }
      else if (tag === "UL") { out.push({ ul: [].map.call(n.querySelectorAll("li"), txt), margin: [0, 2, 0, 6] }); }
      else if (tag === "P") {
        out.push(cls.contains("ai-note") ? { text: txt(n), italics: true, color: C.muted, fontSize: 7.5, margin: [0, 0, 0, 6] }
                                         : { text: txt(n), margin: [0, 0, 0, 6] });
      }
      else if (cls.contains("foot")) {
        out.push({ text: txt(n), fontSize: 7, color: C.muted, margin: [0, 14, 0, 0] });
      }
    });
    return out;
  }

  function incidentId(root) {
    var meta = root.querySelector(".rhead .meta");
    var m = /Incident ID:\s*([A-Z0-9-]+)/.exec(meta && meta.firstElementChild ? meta.firstElementChild.textContent : "");
    return m ? m[1] : "SOC-incident-report";
  }

  function makePdf() {
    var root = document.getElementById("report");
    var id = incidentId(root);
    var doc = {
      pageSize: "LETTER",
      pageMargins: [40, 40, 40, 44],
      info: { title: "Security Incident Report " + id, author: "AI SOC Squirrel (bounded Gemini AI agent)",
              subject: "Tucker Payment Processing (fictional) - live attack demonstration", creator: "tuckerpaymentprocessing.com" },
      defaultStyle: { font: "Roboto", fontSize: 9, color: C.ink, lineHeight: 1.15 },
      content: convert(root),
      footer: function (page, pages) {
        return { columns: [
          { text: "Tucker Payment Processing - Security Incident Report " + id, fontSize: 7, color: C.muted },
          { text: "Page " + page + " of " + pages, alignment: "right", fontSize: 7, color: C.muted } ],
          margin: [40, 14, 40, 0] };
      },
      // Keep a section heading together with what follows it.
      pageBreakBefore: function (node, after) { return node.headlineLevel === 1 && after.length < 3; }
    };
    window.pdfMake.createPdf(doc).download(id + ".pdf");
  }

  function init() {
    var btn = document.getElementById("save-pdf");
    if (!btn) { return; }
    btn.addEventListener("click", function () {
      if (!document.querySelector("#report .rhead")) { return; }      // the report hasn't loaded (yet)
      var label = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Preparing PDF...";
      loadLibrary()
        .then(makePdf)
        .catch(function () { window.print(); })                    // fallback: the browser's print-to-PDF
        .then(function () { btn.disabled = false; btn.textContent = label; });
    });
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
