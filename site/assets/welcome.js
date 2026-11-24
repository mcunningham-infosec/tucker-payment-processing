/*
 * welcome.js - shows Tucker's welcome speech bubble once per browser session.
 * No cookies and nothing sent anywhere: "already seen" is kept in sessionStorage,
 * which the browser clears when the tab/session ends.
 */
(function () {
  "use strict";

  var KEY = "tucker-welcome-seen";

  // Read the "seen" flag. Storage can be blocked (private mode, strict settings),
  // so any error just means "not seen" and the bubble shows.
  function alreadySeen() {
    try { return window.sessionStorage.getItem(KEY) === "1"; } catch (e) { return false; }
  }

  // Remember that the visitor closed the bubble for the rest of this session.
  function markSeen() {
    try { window.sessionStorage.setItem(KEY, "1"); } catch (e) { /* ignore */ }
  }

  // Show the bubble shortly after load, then wire up the close button and Escape key.
  function init() {
    var bubble = document.getElementById("welcome");
    var close = document.getElementById("welcome-close");
    if (!bubble || !close || alreadySeen()) { return; }

    window.setTimeout(function () {
      bubble.hidden = false;
      close.focus({ preventScroll: true });
    }, 600);

    function hide() { bubble.hidden = true; markSeen(); }
    close.addEventListener("click", hide);
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !bubble.hidden) { hide(); } });
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
