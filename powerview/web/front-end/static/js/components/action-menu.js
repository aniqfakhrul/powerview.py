export function createActionMenu({ trigger, menu }) {
  const items = () => [...menu.querySelectorAll('[role="menuitem"]:not(:disabled)')];

  function place() {
    const rect = trigger.getBoundingClientRect();
    const width = menu.offsetWidth;
    menu.style.top = `${rect.bottom + 6}px`;
    menu.style.left = `${Math.max(8, Math.min(rect.right - width, window.innerWidth - width - 8))}px`;
  }

  menu.addEventListener('beforetoggle', (event) => trigger.setAttribute('aria-expanded', String(event.newState === 'open')));

  menu.addEventListener('toggle', (event) => {
    if (event.newState === 'open') {
      place();
      (items()[0] ?? menu).focus();
    } else if (menu.contains(document.activeElement) || document.activeElement === document.body) trigger.focus();
  });

  menu.addEventListener('click', (event) => {
    if (event.target.closest('[role="menuitem"]')) menu.hidePopover();
  });

  menu.addEventListener('keydown', (event) => {
    const list = items();
    if (!list.length) return;
    const index = list.indexOf(document.activeElement);
    const next = { ArrowDown: index + 1, ArrowUp: index - 1, Home: 0, End: list.length - 1 }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    list[(next + list.length) % list.length].focus();
  });
}
