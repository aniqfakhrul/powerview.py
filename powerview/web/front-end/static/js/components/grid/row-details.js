import { element } from '../../core/dom.js';

export function createRowDetails({ root, getEntry, details }) {
  const title = root.querySelector('[data-panel-title]');
  const body = root.querySelector('[data-panel-body]');
  const actions = root.querySelector('[data-panel-actions]');
  root.querySelector('[data-panel-tabs]').hidden = true;
  root.querySelector('[data-panel-filter-host]').hidden = true;
  let current = null;

  function render() {
    if (!current) return;
    const entry = getEntry(current);
    if (!entry) return;
    title.replaceChildren(element('span', '', details.title(entry)));
    actions.replaceChildren(...(details.actions?.(entry) ?? []));
    details.render(body, entry);
  }

  return {
    canLeave: () => true,
    open(key) { current = key; render(); },
    refreshSummary: render,
    refreshActions() {},
  };
}
