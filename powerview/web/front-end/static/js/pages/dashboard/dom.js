import { button, element } from '../../core/dom.js';

export function bar(width) {
  const node = element('span', 'loading-bar');
  node.style.width = width;
  return node;
}

export function skeletonItem(className, ...children) {
  const item = element('div', `loading-row ${className}`.trim());
  item.setAttribute('aria-hidden', 'true');
  item.append(...children);
  return item;
}

export function settle(host, waiting, hasData) {
  host.setAttribute('aria-busy', String(waiting));
  host.classList.toggle('is-refreshing', waiting && hasData);
  return waiting && !hasData;
}

export function retryButton(view, source) {
  const action = button('Retry', { className: 'dashboard__text-action' });
  action.disabled = view.collecting;
  action.addEventListener('click', () => view.retry(source));
  return action;
}

export function unavailable(view, source, text) {
  const note = element('p', 'dashboard__empty', `${text} `);
  note.append(retryButton(view, source));
  return note;
}

export function choice(className, label) {
  const control = element('button', className);
  control.type = 'button';
  control.setAttribute('role', 'radio');
  const name = element('span', '', label);
  const value = element('span', 'dashboard__signal-count');
  control.append(name, value);
  return { control, name, value };
}

export function check(control, checked) {
  control.setAttribute('aria-checked', String(checked));
  control.tabIndex = checked ? 0 : -1;
}

export function choiceGroup(host) {
  host.addEventListener('keydown', (event) => {
    const choices = [...host.querySelectorAll('[role="radio"]:not(:disabled)')];
    const index = choices.indexOf(event.target);
    const next = { ArrowDown: index + 1, ArrowRight: index + 1, ArrowUp: index - 1, ArrowLeft: index - 1, Home: 0, End: choices.length - 1 }[event.key];
    if (index < 0 || next === undefined) return;
    event.preventDefault();
    const target = choices[(next + choices.length) % choices.length];
    target.focus();
    target.click();
  });
}

export function remember(name, value) {
  const url = new URL(location.href);
  if (value) url.searchParams.set(name, value); else url.searchParams.delete(name);
  history.replaceState(null, '', url);
}

export function createLinks(root) {
  const page = (name) => new URL(root.dataset[name] ?? root.dataset.explorer, location.origin);
  function object(record, label = record.name, name = 'explorer') {
    if (!record.dn) return element('span', '', label);
    const link = element('a', 'dashboard__object', label);
    const url = page(name);
    url.searchParams.set('dn', record.dn);
    link.href = url;
    link.title = record.dn;
    link.dataset.inspectDn = record.dn;
    return link;
  }
  return { page, object };
}
