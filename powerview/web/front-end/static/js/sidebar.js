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
    toggle.title = `${label} ([)`;
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
      if (collapsed && sidebar.matches(':hover')) sidebar.classList.add('is-settling');
      apply();
      try {
        if (collapsed) localStorage.setItem(key, 'collapsed');
        else localStorage.removeItem(key);
      } catch {}
    });
    sidebar.addEventListener('pointerleave', () => sidebar.classList.remove('is-settling'));
    document.addEventListener('keydown', (event) => {
      if (event.key !== '[' || event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey) return;
      if (event.target instanceof Element && event.target.closest('input, textarea, select, [contenteditable]')) return;
      if (!matchMedia('(min-width: 721px)').matches) return;
      event.preventDefault();
      toggle.click();
    });
  });
  window.addEventListener('storage', (event) => {
    if (event.key !== key && event.key !== null) return;
    collapsed = event.newValue === 'collapsed';
    apply();
  });
})();
