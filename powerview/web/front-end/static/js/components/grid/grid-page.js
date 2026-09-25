import { createDirectory, entryFromRecord } from '../../core/directory.js';
import { button, element, icon } from '../../core/dom.js';
import { namingContext, sameDN } from '../../core/dn.js';
import { createMutationGuard } from '../../core/mutation-guard.js';
import { createObjectPanel } from '../object-panel/index.js';
import { createResizer } from '../resizer.js';
import { createStatus } from '../status.js';
import { notify } from '../notify.js';
import { createFieldsMenu } from './fields-menu.js';
import { createSearchMenu } from './search-menu.js';

const PAGE_SIZE = 200;
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

export function createGridPage({ root, endpoint, noun, columnSet, search: searchConfig = {} }) {
  const directory = createDirectory(new URL(root.dataset.apiRoot, window.location.origin));
  const scroller = document.querySelector('#grid-scroll');
  const head = document.querySelector('#grid-head');
  const body = document.querySelector('#grid-body');
  const message = document.querySelector('#grid-message');
  const count = document.querySelector('#grid-count');
  const filter = document.querySelector('#grid-filter');
  const refresh = document.querySelector('#grid-refresh');
  const panelRoot = document.querySelector('#object-panel');
  const explorerLink = document.querySelector('#panel-explorer');
  const gridMain = document.querySelector('.grid-main');
  const panelResizer = document.querySelector('#panel-resizer');
  const overlay = matchMedia('(max-width: 1100px)');
  let returnFocus = null;
  const status = createStatus();
  let selectedDN = '';
  let rootDN = '';
  let search = {};

  let columnKeys = columnSet.load();
  let columns = columnSet.columns(columnKeys);

  const cellText = (column, entry) => column.text(entry.record, entry) || '';

  let entries = [];
  let visible = [];
  let rendered = 0;
  let sortKey = 'name';
  let sortDirection = 1;
  let controller;

  const headers = new Map();

  function buildHead() {
    const index = element('th', 'col-index');
    index.scope = 'col';
    index.append(element('span', 'visually-hidden', 'Row'));
    head.replaceChildren(index);
    headers.clear();
    for (const column of columns) {
      const th = element('th', column.key === 'name' ? 'col-name' : '');
      th.scope = 'col';
      th.style.width = `${column.width}px`;
      th.dataset.key = column.key;
      if (column.hint) th.title = column.hint;
      const control = button('', { className: 'column-sort' });
      control.append(icon(column.icon), element('span', 'column-sort__label', column.label), icon('chevron-right', 'column-sort__direction'));
      control.disabled = true;
      control.addEventListener('click', () => {
        sortDirection = sortKey === column.key ? -sortDirection : 1;
        sortKey = column.key;
        update();
      });
      th.append(control);
      head.append(th);
      headers.set(column.key, th);
    }
  }

  function setSortable(enabled) {
    for (const th of headers.values()) th.querySelector('button').disabled = !enabled;
  }

  function showSort() {
    for (const [key, th] of headers) {
      if (key === sortKey) th.setAttribute('aria-sort', sortDirection > 0 ? 'ascending' : 'descending');
      else th.removeAttribute('aria-sort');
    }
  }

  function row(entry, index) {
    const tr = element('tr');
    tr.tabIndex = index === 0 ? 0 : -1;
    tr.dataset.dn = entry.dn;
    tr.setAttribute('aria-selected', String(sameDN(entry.dn, selectedDN)));
    tr.setAttribute('aria-rowindex', String(index + 2));
    tr.append(element('td', 'col-index', String(index + 1)));
    for (const column of columns) {
      const td = element('td', column.key === 'name' ? 'col-name' : '');
      const value = cellText(column, entry);
      if (column.render) td.append(column.render(entry.record, entry));
      else if (value) { td.textContent = value; td.title = value; }
      else td.append(element('span', 'cell-muted', '—'));
      tr.append(td);
    }
    return tr;
  }

  const sentinel = element('tr', 'grid-sentinel');
  const sentinelCell = element('td');
  sentinel.append(sentinelCell);
  const observer = new IntersectionObserver((observed) => {
    if (observed.some((item) => item.isIntersecting)) renderMore();
  }, { root: scroller, rootMargin: '400px' });

  function renderMore() {
    const next = visible.slice(rendered, rendered + PAGE_SIZE);
    sentinel.remove();
    body.append(...next.map((entry, offset) => row(entry, rendered + offset)));
    rendered += next.length;
    if (rendered < visible.length) { body.append(sentinel); observer.observe(sentinel); }
  }

  function update() {
    const query = filter.value.trim().toLocaleLowerCase();
    const column = columns.find((item) => item.key === sortKey) ?? columnSet.name;
    const key = column.sort ? (entry) => column.sort(entry.record, entry) : (entry) => cellText(column, entry) || null;
    sentinelCell.colSpan = columns.length + 1;
    visible = entries
      .filter((entry) => !query || columns.some((item) => cellText(item, entry).toLocaleLowerCase().includes(query)))
      .sort((a, b) => {
        const left = key(a); const right = key(b);
        if (left == null || right == null) return left == null ? (right == null ? 0 : 1) : -1;
        return sortDirection * (typeof left === 'number' ? left - right : collator.compare(left, right));
      });
    showSort();
    body.replaceChildren();
    rendered = 0;
    renderMore();
    document.querySelector('#grid').setAttribute('aria-rowcount', String(visible.length + 1));
    count.textContent = query ? `${visible.length} of ${entries.length} ${noun.plural}` : `${entries.length} ${entries.length === 1 ? noun.singular : noun.plural}`;
    message.replaceChildren();
    if (entries.length && !visible.length) showMessage(`No ${noun.plural} match`, 'Try a different filter.');
  }

  function showMessage(title, description, retry) {
    const box = element('div');
    box.append(element('h2', '', title), element('p', '', description));
    if (retry) {
      const action = button('Retry', { iconName: 'refresh' });
      action.addEventListener('click', retry);
      box.append(action);
    }
    message.replaceChildren(box);
  }

  function skeleton() {
    body.replaceChildren();
    for (let index = 0; index < 12; index += 1) {
      const tr = element('tr');
      tr.setAttribute('aria-hidden', 'true');
      tr.append(element('td', 'col-index'));
      for (const column of columns) tr.append(element('td', column.key === 'name' ? 'col-name' : ''));
      body.append(tr);
    }
  }

  async function load(fresh = false) {
    controller?.abort();
    controller = new AbortController();
    const { signal } = controller;
    filter.disabled = true;
    refresh.disabled = true;
    setSortable(false);
    skeleton();
    message.replaceChildren();
    count.textContent = `Loading ${noun.plural}…`;
    try {
      const result = await directory.list(endpoint, { signal, fresh, properties: columnSet.properties(columns), search });
      if (signal.aborted) return false;
      entries = result;
      filter.disabled = false;
      setSortable(true);
      update();
      if (!entries.length) showMessage(`No ${noun.plural} found`, `The connected directory returned no ${noun.singular} objects.`);
      return true;
    } catch (error) {
      if (signal.aborted) return false;
      entries = [];
      body.replaceChildren();
      count.textContent = '';
      showMessage(`Cannot load ${noun.plural}`, error.message, () => load(true));
      return false;
    } finally {
      if (!signal.aborted) refresh.disabled = false;
    }
  }

  function explorerURL(dn) {
    const url = new URL(root.dataset.explorer, window.location.origin);
    url.searchParams.set('dn', dn);
    return url;
  }

  function remember(dn) {
    const url = new URL(window.location.href);
    if (dn) url.searchParams.set('dn', dn); else url.searchParams.delete('dn');
    history.replaceState(null, '', url);
  }

  function markSelected() {
    for (const tr of body.querySelectorAll('tr[data-dn]')) tr.setAttribute('aria-selected', String(sameDN(tr.dataset.dn, selectedDN)));
  }

  function syncOverlay() {
    const covering = overlay.matches && !panelRoot.hidden;
    gridMain.inert = covering;
    for (const node of [document.querySelector('.grid-page > .toolbar'), document.querySelector('.workspace > .sidebar')]) {
      if (node) node.inert = covering;
    }
    if (covering && !panelRoot.contains(document.activeElement)) {
      panelRoot.querySelector('[role="tab"][aria-selected="true"]')?.focus();
    }
  }

  function select(dn) {
    if (!panel.canLeave()) return;
    const opening = panelRoot.hidden;
    if (opening) returnFocus = document.activeElement;
    selectedDN = dn;
    markSelected();
    remember(dn);
    explorerLink.href = explorerURL(dn);
    panelRoot.hidden = false;
    panelResizer.hidden = false;
    syncOverlay();
    if (opening && overlay.matches) panelRoot.querySelector('[role="tab"][aria-selected="true"]')?.focus();
    panel.open(dn);
  }

  function closePanel() {
    if (!panel.canLeave()) return;
    const previous = selectedDN;
    selectedDN = '';
    panelRoot.hidden = true;
    panelResizer.hidden = true;
    syncOverlay();
    markSelected();
    remember('');
    const row = body.querySelector(`tr[data-dn="${CSS.escape(previous)}"]`);
    (row ?? (returnFocus?.isConnected ? returnFocus : null))?.focus();
    returnFocus = null;
  }

  function removeEntry(dn) {
    const position = visible.findIndex((entry) => sameDN(entry.dn, dn));
    const scrollTop = scroller.scrollTop;
    entries = entries.filter((entry) => !sameDN(entry.dn, dn));
    selectedDN = '';
    panelRoot.hidden = true;
    panelResizer.hidden = true;
    syncOverlay();
    remember('');
    update();
    scroller.scrollTop = scrollTop;
    const rows = body.querySelectorAll('tr[data-dn]');
    const next = rows[Math.min(Math.max(position, 0), rows.length - 1)];
    if (next) {
      for (const row of rows) row.tabIndex = row === next ? 0 : -1;
      next.focus({ preventScroll: true });
    } else scroller.focus({ preventScroll: true });
    returnFocus = null;
  }

  function reconcile(record) {
    if (!record) return;
    const updated = entryFromRecord(record);
    const index = entries.findIndex((entry) => sameDN(entry.dn, updated.dn));
    if (index < 0) return;
    entries[index] = updated;
    const scrollTop = scroller.scrollTop;
    update();
    const position = visible.findIndex((entry) => sameDN(entry.dn, selectedDN));
    while (position >= rendered && rendered < visible.length) renderMore();
    scroller.scrollTop = scrollTop;
  }

  const guard = createMutationGuard({ onBlocked: () => notify.info('Wait for the current change to finish.') });
  const panel = createObjectPanel({
    root: panelRoot,
    directory,
    status,
    guard,
    scope: (dn) => namingContext(dn, [rootDN]) ?? rootDN,
    onNavigate: select,
    onSaved: async () => reconcile(await panel.open(selectedDN, { fresh: true })),
    onDeleted: (record) => removeEntry(record.dn),
  });

  document.querySelector('#panel-close').addEventListener('click', closePanel);
  explorerLink.addEventListener('click', (event) => { if (!panel.canLeave()) event.preventDefault(); });
  overlay.addEventListener('change', syncOverlay);
  createResizer({
    root,
    handle: panelResizer,
    pane: panelRoot,
    property: '--panel-width',
    storageKey: 'powerview.panelWidth',
    min: 360,
    max: 960,
    edge: 'start',
  });
  panelRoot.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !event.defaultPrevented) { event.preventDefault(); closePanel(); }
  });

  body.addEventListener('click', (event) => {
    const link = event.target.closest('[data-dn-link]');
    if (link) { select(link.dataset.dnLink); return; }
    const tr = event.target.closest('tr[data-dn]');
    if (tr) select(tr.dataset.dn);
  });

  body.addEventListener('keydown', (event) => {
    if (event.target.closest('[data-dn-link]')) return;
    const tr = event.target.closest('tr[data-dn]');
    if (!tr) return;
    let target;
    if (event.key === 'ArrowDown') target = tr.nextElementSibling;
    else if (event.key === 'ArrowUp') target = tr.previousElementSibling;
    else if (event.key === 'Home') target = body.firstElementChild;
    else if (event.key === 'End') {
      while (rendered < visible.length) renderMore();
      target = [...body.querySelectorAll('tr[data-dn]')].at(-1);
    }
    else if (event.key === 'Enter') { select(tr.dataset.dn); return; }
    else return;
    event.preventDefault();
    if (!target?.dataset.dn) return;
    tr.tabIndex = -1;
    target.tabIndex = 0;
    target.focus();
  });

  filter.addEventListener('input', update);
  filter.addEventListener('keydown', (event) => { if (event.key === 'Escape' && filter.value) { filter.value = ''; update(); } });
  refresh.addEventListener('click', () => load(true));

  directory.schemaAttributes(columnSet.objectClass)
    .then((attributes) => {
      if (!attributes) return;
      columnSet.setSchema(attributes);
      fieldsMenu.schemaChanged();
      if (!columnKeys.some((key) => key.startsWith('attr:'))) return;
      const focusedHeader = document.activeElement?.closest('#grid-head th')?.dataset.key;
      const focusedRow = document.activeElement?.closest('#grid-body tr[data-dn]')?.dataset.dn;
      const scrollTop = scroller.scrollTop;
      const scrollLeft = scroller.scrollLeft;
      columns = columnSet.columns(columnKeys);
      buildHead();
      if (!filter.disabled) { setSortable(true); update(); }
      scroller.scrollTop = scrollTop;
      scroller.scrollLeft = scrollLeft;
      if (focusedHeader) head.querySelector(`th[data-key="${CSS.escape(focusedHeader)}"] button`)?.focus({ preventScroll: true });
      else if (focusedRow) body.querySelector(`tr[data-dn="${CSS.escape(focusedRow)}"]`)?.focus({ preventScroll: true });
    })
    .catch(() => {});

  const domainReady = directory.domain()
    .then((domain) => { rootDN = domain?.root_dn ?? ''; return rootDN; })
    .catch(() => '');
  const fieldsMenu = createFieldsMenu({
    trigger: document.querySelector('#grid-fields'),
    menu: document.querySelector('#fields-menu'),
    columnSet,
    getKeys: () => columnKeys,
    onApply(keys) {
      columnKeys = keys;
      columnSet.save(keys);
      columns = columnSet.columns(keys);
      if (!columns.some((column) => column.key === sortKey)) { sortKey = 'name'; sortDirection = 1; }
      buildHead();
      fieldsMenu.refresh();
      load();
    },
  });

  createSearchMenu({
    trigger: document.querySelector('#grid-search'),
    menu: document.querySelector('#search-menu'),
    defaultBase: () => rootDN,
    ...searchConfig,
    onApply(value) { search = value; load(true); },
  });

  buildHead();
  load().then((loaded) => {
    const requested = new URLSearchParams(window.location.search).get('dn');
    if (loaded && requested) select(requested);
  });

  return {
    directory,
    status,
    domainReady,
    rootDN: () => rootDN,
    async reloadAndFind(text) {
      if (!(await load(true))) return false;
      filter.value = text;
      update();
      return true;
    },
  };
}
