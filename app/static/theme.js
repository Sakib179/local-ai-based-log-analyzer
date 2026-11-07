"use strict";

// Apply before styles load to avoid flashing the wrong theme on reload.
(() => {
  let theme;
  try { theme = localStorage.getItem("local-ai-theme"); } catch { /* Optional preference storage. */ }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.dataset.theme = theme;
})();
