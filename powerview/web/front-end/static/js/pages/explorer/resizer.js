const STORAGE_KEY = 'powerview.explorer.treeWidth';
const MIN_WIDTH = 220;
const STEP = 24;

function stored() {
  try { return Number(localStorage.getItem(STORAGE_KEY)) || 0; } catch { return 0; }
}

function persist(width) {
  try { localStorage.setItem(STORAGE_KEY, String(width)); } catch { /* per-viewer convenience only */ }
}

export function createResizer(root, handle, pane) {
  const maxWidth = () => Math.max(MIN_WIDTH, Math.min(720, root.clientWidth * 0.6));
  const clamp = (width) => Math.round(Math.min(maxWidth(), Math.max(MIN_WIDTH, width)));

  function apply(width, save = false) {
    const next = clamp(width);
    root.style.setProperty('--tree-width', `${next}px`);
    handle.setAttribute('aria-valuenow', String(next));
    handle.setAttribute('aria-valuemin', String(MIN_WIDTH));
    handle.setAttribute('aria-valuemax', String(Math.round(maxWidth())));
    if (save) persist(next);
  }

  function reset() {
    root.style.removeProperty('--tree-width');
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
    handle.setAttribute('aria-valuenow', String(pane.getBoundingClientRect().width));
  }

  handle.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = pane.getBoundingClientRect().width;
    handle.setPointerCapture(event.pointerId);
    handle.classList.add('is-dragging');
    root.classList.add('is-resizing');
    const move = (moveEvent) => apply(startWidth + moveEvent.clientX - startX);
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
    if (event.key === 'ArrowLeft') apply(width - STEP, true);
    else if (event.key === 'ArrowRight') apply(width + STEP, true);
    else if (event.key === 'Home') apply(MIN_WIDTH, true);
    else if (event.key === 'End') apply(maxWidth(), true);
    else return;
    event.preventDefault();
  });

  handle.addEventListener('dblclick', reset);
  if (stored()) apply(stored());
  else handle.setAttribute('aria-valuenow', String(Math.round(pane.getBoundingClientRect().width)));
}
