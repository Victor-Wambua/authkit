// Runs before first paint so a saved theme choice never flashes the wrong colours.
try {
  var saved = localStorage.getItem('authkit-theme');
  if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
} catch (e) { /* storage unavailable: follow the system setting */ }
