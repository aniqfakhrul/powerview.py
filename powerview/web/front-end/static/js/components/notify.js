import { button, element, icon } from '../core/dom.js';

const MAX_VISIBLE = 3;
const DISMISS_AFTER = 4000;
const TONES = {
  success: { icon: 'check', persistent: false },
  info: { icon: 'info', persistent: false },
  warn: { icon: 'alert', persistent: true },
  error: { icon: 'alert', persistent: true },
};

let region;
const active = new Map();
let politeAnnouncer;
let returnTarget = null;
let assertiveAnnouncer;

function mount() {
  if (region?.isConnected) return;
  region = document.querySelector('#toasts');
  if (!region) {
    region = element('section', 'toasts');
    region.id = 'toasts';
    region.setAttribute('aria-label', 'Notifications');
    document.body.append(region);
  }
  region.addEventListener('focusin', (event) => {
    if (event.relatedTarget && !region.contains(event.relatedTarget)) returnTarget = event.relatedTarget;
  });
  politeAnnouncer = announcer('polite');
  assertiveAnnouncer = announcer('assertive');
}

function announcer(level) {
  const node = element('div', 'visually-hidden');
  node.setAttribute('aria-live', level);
  node.setAttribute('aria-atomic', 'true');
  region.after(node);
  return node;
}

function announce(tone, text) {
  const target = tone === 'error' ? assertiveAnnouncer : politeAnnouncer;
  target.textContent = '';
  requestAnimationFrame(() => { target.textContent = text; });
}

function focusAfterRemoving(toast) {
  if (!toast.contains(document.activeElement)) return;
  const neighbour = toast.nextElementSibling ?? toast.previousElementSibling;
  const target = neighbour?.querySelector('.toast__close')
    ?? (returnTarget?.isConnected ? returnTarget : null)
    ?? document.querySelector('#main-content');
  target?.focus();
}

function removeToast(toast) {
  focusAfterRemoving(toast);
  toast.remove();
  for (const [key, entry] of active) if (entry.element === toast) active.delete(key);
}

function show(tone, text, { action } = {}) {
  mount();
  const key = `${tone}:${text}`;
  const existing = active.get(key);
  if (existing && !action) {
    existing.refresh();
    announce(tone, text);
    return existing;
  }
  const toast = element('div', `toast toast--${tone}`);
  toast.dataset.tone = tone;
  const body = element('p', 'toast__text', text);
  toast.append(icon(TONES[tone].icon, 'toast__icon'), body);
  if (action) {
    const actionButton = button(action.label, { className: 'toast__action' });
    actionButton.addEventListener('click', () => { dismiss(); action.run(); });
    toast.append(actionButton);
  }
  const close = button('', { iconName: 'close', className: 'icon-button toast__close', ariaLabel: 'Dismiss notification' });
  close.addEventListener('click', () => dismiss());
  toast.append(close);

  let timer;
  let hovered = false;
  let focused = false;
  function schedule() {
    clearTimeout(timer);
    if (!TONES[tone].persistent && !hovered && !focused) timer = setTimeout(dismiss, DISMISS_AFTER);
  }
  function dismiss() {
    clearTimeout(timer);
    removeToast(toast);
  }
  function refresh() {
    region.append(toast);
    toast.classList.remove('toast--repeat');
    void toast.offsetWidth;
    toast.classList.add('toast--repeat');
    schedule();
  }
  const handle = { dismiss, refresh, element: toast };
  toast.addEventListener('pointerenter', () => { hovered = true; schedule(); });
  toast.addEventListener('pointerleave', () => { hovered = false; schedule(); });
  toast.addEventListener('focusin', () => { focused = true; schedule(); });
  toast.addEventListener('focusout', (event) => {
    if (toast.contains(event.relatedTarget)) return;
    focused = false;
    schedule();
  });

  region.append(toast);
  active.set(key, handle);
  while (region.childElementCount > MAX_VISIBLE) removeToast(region.firstElementChild);
  announce(tone, text);
  schedule();
  return handle;
}

export const notify = {
  success: (text, options) => show('success', text, options),
  info: (text, options) => show('info', text, options),
  warn: (text, options) => show('warn', text, options),
  error: (text, options) => show('error', text, options),
};
