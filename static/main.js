(function () {
  const root = document.documentElement;
  const toggle = document.getElementById("themeToggle");
  const STORAGE_KEY = "forensis-theme";

  function applyTheme(theme) {
    root.setAttribute("data-bs-theme", theme);
    if (toggle) {
      toggle.checked = theme === "dark";
    }
  }

  function loadTheme() {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark") {
      return saved;
    }
    return "dark"; // default
  }

  document.addEventListener("DOMContentLoaded", function () {
    const theme = loadTheme();
    applyTheme(theme);

    if (toggle) {
      toggle.addEventListener("change", function () {
        const next = toggle.checked ? "dark" : "light";
        applyTheme(next);
        window.localStorage.setItem(STORAGE_KEY, next);
      });
    }
  });
})();
