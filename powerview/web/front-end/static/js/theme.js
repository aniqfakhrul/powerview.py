(() => {
  const key = 'powerview.theme';
  const normalize = (value) => ['light', 'dark'].includes(value) ? value : 'system';
  const apply = (value) => {
    const theme = normalize(value);
    if (theme === 'system') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    const control = document.querySelector('#theme-preference');
    if (control) control.value = theme;
  };
  let preference = 'system';
  try { preference = normalize(localStorage.getItem(key)); } catch {}
  apply(preference);
  document.addEventListener('DOMContentLoaded', () => {
    const control = document.querySelector('#theme-preference');
    if (!control) return;
    control.value = preference;
    control.addEventListener('change', () => {
      preference = normalize(control.value);
      apply(preference);
      try {
        if (preference === 'system') localStorage.removeItem(key);
        else localStorage.setItem(key, preference);
      } catch {}
    });
  });
  window.addEventListener('storage', (event) => {
    if (event.key !== key && event.key !== null) return;
    preference = normalize(event.newValue);
    apply(preference);
  });
})();
