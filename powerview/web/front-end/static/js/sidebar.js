(() => {
  const key = 'powerview.sidebar';
  const root = document.documentElement;
  let collapsed = false;

  const apply = () => {
    if (collapsed) root.dataset.sidebar = 'collapsed';
    else delete root.dataset.sidebar;
    const toggle = document.querySelector('#sidebar-toggle');
    if (!toggle) return;
    const label = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
    toggle.setAttribute('aria-expanded', String(!collapsed));
    toggle.setAttribute('aria-label', label);
    toggle.title = label;
  };

  try { collapsed = localStorage.getItem(key) === 'collapsed'; } catch {}
  apply();
  document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.querySelector('.sidebar');
    const toggle = document.querySelector('#sidebar-toggle');
    apply();
    if (!sidebar || !toggle) return;
    toggle.addEventListener('click', () => {
      collapsed = !collapsed;
      if (collapsed) sidebar.classList.add('is-settling');
      apply();
      try {
        if (collapsed) localStorage.setItem(key, 'collapsed');
        else localStorage.removeItem(key);
      } catch {}
    });
    sidebar.addEventListener('pointerleave', () => sidebar.classList.remove('is-settling'));
  });
  window.addEventListener('storage', (event) => {
    if (event.key !== key && event.key !== null) return;
    collapsed = event.newValue === 'collapsed';
    apply();
  });
})();
