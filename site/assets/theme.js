/*
 * theme.js - the "Play the Theme Song!" button: Play starts the song, Stop stops it and rewinds.
 * Self-hosted MP3, no third-party player (so the site's strict Content Security Policy stays intact).
 * Nothing plays or downloads until the visitor clicks.
 *
 * Tucker Payment Processing by Michael Cunningham. (c) 2026. Built with AI-assisted development.
 */
(function () {
  "use strict";

  // Format seconds as m:ss.
  function clock(t) {
    t = Math.max(0, Math.floor(t || 0));
    return Math.floor(t / 60) + ":" + String(t % 60).padStart(2, "0");
  }

  // Wire up the button once the page is ready.
  function init() {
    var btn = document.getElementById("theme-btn");
    var audio = document.getElementById("theme-audio");
    var time = document.getElementById("theme-time");
    if (!btn || !audio) { return; }
    var lbl = btn.querySelector(".lbl"), ico = btn.querySelector(".ico");

    // Show the button as playing or stopped.
    function setPlaying(on) {
      btn.setAttribute("aria-pressed", on ? "true" : "false");
      btn.classList.toggle("playing", on);
      lbl.textContent = on ? "Stop" : "Play the Theme Song!";
      ico.textContent = on ? "\u25A0" : "\u266B";
      if (!on) { time.textContent = ""; }
    }

    // Stop and rewind to the start.
    function stop() { audio.pause(); audio.currentTime = 0; setPlaying(false); }

    btn.addEventListener("click", function () {
      if (audio.paused) {
        var p = audio.play();
        setPlaying(true);
        if (p && p.catch) { p.catch(function () { setPlaying(false); }); }
      } else {
        stop();
      }
    });
    audio.addEventListener("timeupdate", function () {
      if (!audio.paused) { time.textContent = clock(audio.currentTime) + " / " + clock(audio.duration); }
    });
    audio.addEventListener("ended", stop);
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
