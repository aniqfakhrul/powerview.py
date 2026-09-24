export function manageTreeOverlay(root, { toggle, closeButton }) {
  const pane = root.querySelector('#directory-pane');
  const inertTargets = [root.querySelector('#object-pane'), root.querySelector('.toolbar'), document.querySelector('.workspace > .sidebar')];
  const mobile = matchMedia('(max-width: 720px)');
  let active = false;

  const focusable = () => [...pane.querySelectorAll('button, input, [tabindex="0"]')]
    .filter((node) => !node.disabled && node.getClientRects().length);

  function sync() {
    active = mobile.matches && root.classList.contains('tree-open');
    for (const node of inertTargets) if (node) node.inert = active;
    toggle.setAttribute('aria-expanded', String(active));
    if (active) {
      pane.setAttribute('role', 'dialog');
      pane.setAttribute('aria-modal', 'true');
      if (!pane.contains(document.activeElement)) focusable()[0]?.focus();
    } else {
      pane.removeAttribute('role');
      pane.removeAttribute('aria-modal');
    }
  }

  function set(open) {
    root.classList.toggle('tree-open', open);
    sync();
    if (!open && mobile.matches) toggle.focus();
  }

  toggle.addEventListener('click', () => set(!root.classList.contains('tree-open')));
  closeButton.addEventListener('click', () => set(false));
  root.addEventListener('keydown', (event) => {
    if (!active) return;
    if (event.key === 'Escape') { event.preventDefault(); set(false); return; }
    if (event.key !== 'Tab') return;
    const items = focusable();
    if (event.shiftKey && document.activeElement === items[0]) { event.preventDefault(); items.at(-1)?.focus(); }
    else if (!event.shiftKey && document.activeElement === items.at(-1)) { event.preventDefault(); items[0]?.focus(); }
  });
  mobile.addEventListener('change', sync);
  sync();

  return { close: () => { if (active) set(false); } };
}
