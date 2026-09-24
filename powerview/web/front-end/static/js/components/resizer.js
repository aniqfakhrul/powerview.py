const STEP = 24;

function stored(key) {
  try { return Number(localStorage.getItem(key)) || 0; } catch { return 0; }
}

function persist(key, width) {
  try {
    if (width) localStorage.setItem(key, String(width));
    else localStorage.removeItem(key);
  } catch { /* per-viewer convenience only */ }
}

export function createResizer({ root, handle, pane, property, storageKey, min, max, edge = 'end' }) {
  const direction = edge === 'end' ? 1 : -1;
  const maxWidth = () => Math.max(min, Math.min(max, root.clientWidth * 0.6));
  const clamp = (width) => Math.round(Math.min(maxWidth(), Math.max(min, width)));

  function describe() {
    handle.setAttribute('aria-valuenow', String(Math.round(pane.getBoundingClientRect().width)));
    handle.setAttribute('aria-valuemin', String(min));
    handle.setAttribute('aria-valuemax', String(Math.round(maxWidth())));
  }

  function apply(width, save = false) {
    const next = clamp(width);
    root.style.setProperty(property, `${next}px`);
    describe();
    if (save) persist(storageKey, next);
  }

  handle.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = pane.getBoundingClientRect().width;
    handle.setPointerCapture(event.pointerId);
    handle.classList.add('is-dragging');
    root.classList.add('is-resizing');
    const move = (moveEvent) => apply(startWidth + direction * (moveEvent.clientX - startX));
    const stop = () => {
      handle.classList.remove('is-dragging');
      root.classList.remove('is-resizing');
      handle.removeEventListener('pointermove', move);
      apply(pane.getBoundingClientRect().width, true);
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', stop, { once: true });
    handle.addEventListener('pointercancel', stop, { once: true });
  });

  handle.addEventListener('keydown', (event) => {
    const width = pane.getBoundingClientRect().width;
    const grow = direction > 0 ? 'ArrowRight' : 'ArrowLeft';
    const shrink = direction > 0 ? 'ArrowLeft' : 'ArrowRight';
    if (event.key === grow) apply(width + STEP, true);
    else if (event.key === shrink) apply(width - STEP, true);
    else if (event.key === 'Home') apply(min, true);
    else if (event.key === 'End') apply(maxWidth(), true);
    else return;
    event.preventDefault();
  });

  handle.addEventListener('dblclick', () => {
    root.style.removeProperty(property);
    persist(storageKey, 0);
    describe();
  });

  if (stored(storageKey)) apply(stored(storageKey));
  else describe();
}
