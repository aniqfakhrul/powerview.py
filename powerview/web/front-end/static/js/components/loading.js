import { element } from '../core/dom.js';

export function beginLoading(host, { signal, onDelay } = {}) {
  if (signal?.aborted) return () => {};
  host.setAttribute('aria-busy', 'true');
  const timer = setTimeout(() => {
    host.classList.add('is-loading-delayed');
    onDelay?.();
  }, 200);
  function finish() {
    clearTimeout(timer);
    signal?.removeEventListener('abort', finish);
    host.classList.remove('is-loading-delayed');
    host.setAttribute('aria-busy', 'false');
  }
  signal?.addEventListener('abort', finish, { once: true });
  return finish;
}

export function skeletonRows(columns, count = 8) {
  return Array.from({ length: count }, (_, index) => {
    const row = element('tr', 'loading-row');
    row.setAttribute('aria-hidden', 'true');
    for (const [position, className] of columns.entries()) {
      const cell = element('td', className);
      if (className !== 'col-index') {
        const bar = element('span', 'loading-bar');
        bar.style.width = `${45 + (index * 7 + position * 11) % 40}%`;
        cell.append(bar);
      }
      row.append(cell);
    }
    return row;
  });
}
