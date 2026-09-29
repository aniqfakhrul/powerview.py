import { isDN } from '../core/dn.js';
import { objectType, recordName } from '../core/directory.js';
import { element, icon } from '../core/dom.js';

const SEARCH_DELAY = 250;
const MIN_QUERY = 2;
const TYPE_ICONS = { user: 'user', group: 'group', computer: 'computer', ou: 'ou', policy: 'policy', domain: 'domain', container: 'folder' };

export function attachObjectSearch({ input, directory, kind, onChoose }) {
  const popup = element('div', 'object-search');
  const list = element('ul', 'object-search__list');
  const status = element('p', 'object-search__status');
  list.id = `object-search-${Math.random().toString(36).slice(2)}`;
  list.setAttribute('role', 'listbox');
  status.setAttribute('aria-live', 'polite');
  popup.hidden = true;
  popup.append(list, status);
  popup.addEventListener('click', (event) => event.preventDefault());
  input.parentElement.classList.add('object-search-host');
  input.after(popup);
  input.autocomplete = 'off';
  input.setAttribute('role', 'combobox');
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-expanded', 'false');
  input.setAttribute('aria-controls', list.id);

  let timer;
  let controller = null;

  function show(records, message = '') {
    list.replaceChildren(...records.map(option));
    status.textContent = message;
    status.hidden = !message;
    popup.hidden = !records.length && !message;
    input.setAttribute('aria-expanded', String(records.length > 0));
  }

  function stop() {
    clearTimeout(timer);
    controller?.abort();
    controller = null;
  }

  function close() {
    stop();
    show([]);
  }

  function choose(record) {
    close();
    input.value = record.dn;
    onChoose(record);
  }

  function option(record) {
    const item = element('li', 'object-search__option');
    const type = objectType(record);
    item.setAttribute('role', 'option');
    item.tabIndex = -1;
    item.append(icon(TYPE_ICONS[type] ?? 'object', `type--${type}`), element('span', '', recordName(record)), element('span', 'object-search__dn', record.dn));
    item.addEventListener('click', () => choose(record));
    return item;
  }

  async function search(text) {
    const pending = new AbortController();
    controller = pending;
    try {
      const { records, more } = await directory.findObjects(text, { kind, signal: pending.signal });
      if (controller !== pending) return;
      show(records, !records.length ? 'No matching objects' : more ? `Showing the first ${records.length} matches; keep typing to narrow the list` : '');
    } catch (failure) {
      if (failure.name !== 'AbortError' && controller === pending) show([], `Search failed: ${failure.message}`);
    }
  }

  input.addEventListener('input', () => {
    stop();
    const text = input.value.trim();
    if (text.length < MIN_QUERY || isDN(text)) { show([]); return; }
    show([], 'Searching…');
    timer = setTimeout(() => search(text), SEARCH_DELAY);
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown' && list.firstElementChild) { event.preventDefault(); list.firstElementChild.focus(); }
  });
  list.addEventListener('keydown', (event) => {
    const current = event.target.closest('[role="option"]');
    if (event.key === 'ArrowDown') { event.preventDefault(); current?.nextElementSibling?.focus(); }
    else if (event.key === 'ArrowUp') { event.preventDefault(); (current?.previousElementSibling ?? input).focus(); }
    else if (event.key === 'Enter' && current) { event.preventDefault(); current.click(); }
  });
  for (const node of [input, popup]) {
    node.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' || popup.hidden) return;
      event.preventDefault();
      event.stopPropagation();
      close();
      input.focus();
    });
    node.addEventListener('focusout', (event) => {
      if (!input.contains(event.relatedTarget) && !popup.contains(event.relatedTarget)) close();
    });
  }

  return { close };
}
