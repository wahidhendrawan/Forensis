document.addEventListener('DOMContentLoaded', () => {
    // Check local storage
    const storedTheme = localStorage.getItem('forensis-theme');
    const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    let currentTheme = storedTheme || (systemDark ? 'dark' : 'light');

    // Apply theme
    document.documentElement.setAttribute('data-bs-theme', currentTheme);
    updateThemeToggle(currentTheme);

    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-bs-theme', currentTheme);
            localStorage.setItem('forensis-theme', currentTheme);
            updateThemeToggle(currentTheme);
        });
    }

    function updateThemeToggle(theme) {
        const icon = document.getElementById('theme-icon');
        const label = document.getElementById('theme-label');
        const toggle = document.getElementById('theme-toggle');
        if (icon) {
            if (theme === 'dark') {
                icon.className = 'fas fa-sun';
                if (label) label.textContent = 'Dark';
                if (toggle) toggle.setAttribute('aria-label', 'Switch to light mode');
            } else {
                icon.className = 'fas fa-moon';
                if (label) label.textContent = 'Light';
                if (toggle) toggle.setAttribute('aria-label', 'Switch to dark mode');
            }
        }
    }
});
