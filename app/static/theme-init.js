(() => {
  let theme = 'dark';
  try {
    const savedTheme = localStorage.getItem('valorynn-theme');
    if (savedTheme === 'light' || savedTheme === 'dark') theme = savedTheme;
  } catch (error) {
    console.warn('Saved theme could not be read; using dark mode.', error);
  }
  document.documentElement.dataset.theme = theme;
})();
