document.addEventListener('DOMContentLoaded', () => {
    // Check local storage
    const storedTheme = localStorage.getItem('forensis-theme');
    const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    let currentTheme = storedTheme || (systemDark ? 'dark' : 'light');

    // Apply theme
    document.documentElement.setAttribute('data-bs-theme', currentTheme);
    updateIcon(currentTheme);

    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-bs-theme', currentTheme);
            localStorage.setItem('forensis-theme', currentTheme);
            updateIcon(currentTheme);
        });
    }

    function updateIcon(theme) {
        const icon = document.getElementById('theme-icon');
        if (icon) {
            if (theme === 'dark') {
                icon.className = 'fas fa-sun';
            } else {
                icon.className = 'fas fa-moon';
            }
        }
    }
});
