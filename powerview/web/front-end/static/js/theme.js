(() => {
  const key = 'powerview.theme';
  const themes = ['system', 'light', 'dark'];
  const normalize = (value) => (['light', 'dark'].includes(value) ? value : 'system');
  const options = () => [...document.querySelectorAll('[data-theme-option]')];
  let preference = 'system';

  const apply = () => {
    if (preference === 'system') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = preference;
    for (const option of options()) {
      const checked = option.dataset.themeOption === preference;
      option.setAttribute('aria-checked', String(checked));
      option.tabIndex = checked ? 0 : -1;
    }
  };

  const choose = (value, focus = false) => {
    preference = normalize(value);
    apply();
    if (focus) options().find((option) => option.dataset.themeOption === preference)?.focus();
    try {
      if (preference === 'system') localStorage.removeItem(key);
      else localStorage.setItem(key, preference);
    } catch {}
  };

  try { preference = normalize(localStorage.getItem(key)); } catch {}
  apply();
  document.addEventListener('DOMContentLoaded', () => {
    apply();
    const group = document.querySelector('.theme-switch');
    if (!group) return;
    group.addEventListener('click', (event) => {
      const option = event.target.closest('[data-theme-option]');
      if (option) choose(option.dataset.themeOption);
    });
    group.addEventListener('keydown', (event) => {
      const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[event.key];
      if (!step) return;
      event.preventDefault();
      choose(themes[(themes.indexOf(preference) + step + themes.length) % themes.length], true);
    });
  });
  window.addEventListener('storage', (event) => {
    if (event.key !== key && event.key !== null) return;
    preference = normalize(event.newValue);
    apply();
  });
})();
