import { beginLoading, skeletonRows } from '../loading.js';
import { createDirectory, entryFromRecord } from '../../core/directory.js';
import { button, element, icon } from '../../core/dom.js';
import { namingContext, sameDN } from '../../core/dn.js';
import { createMutationGuard } from '../../core/mutation-guard.js';
import { createObjectPanel } from '../object-panel/index.js';
import { createResizer } from '../resizer.js';
import { createStatus } from '../status.js';
import { notify } from '../notify.js';
import { expandChips, fitChips } from './chips.js';
import { createActionMenu } from '../action-menu.js';
import { downloadCsv, toCsv } from './csv-export.js';
import { createColumnFilter, filterSpec, isActive, matchesFilter } from './column-filter.js';
import { createFieldsMenu } from './fields-menu.js';
import { createSearchMenu, validateFilter } from './search-menu.js';
import { createRowDetails } from './row-details.js';

const PAGE_SIZE = 200;
const MIN_COLUMN_WIDTH = 64;
const MAX_COLUMN_WIDTH = 800;
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

function linkedSearch() {
  const filter = new URLSearchParams(window.location.search).get('ldapfilter') ?? '';
  return filter && !validateFilter(filter) ? { filter } : {};
}

export function createGridPage({ root, endpoint, noun, columnSet, search: searchConfig = {}, fetch: fetchEntries, deletable = true, describeRemoval, isProtected = () => false, afterDelete, summary, panelActions, autoLoad = true, initialMessage, emptyMessage, details, onLoadState, exportName = root.id }) {
  const directory = createDirectory(new URL(root.dataset.apiRoot, window.location.origin));
  const scroller = document.querySelector('#grid-scroll');
  const head = document.querySelector('#grid-head');
  const body = document.querySelector('#grid-body');
  const message = document.querySelector('#grid-message');
  const count = document.querySelector('#grid-count');
  const filter = document.querySelector('#grid-filter');
  const refresh = document.querySelector('#grid-refresh');
  const exportButton = document.querySelector('#grid-export');
  const panelRoot = document.querySelector('#object-panel');
  const explorerLink = document.querySelector('#panel-explorer');
  const gridMain = document.querySelector('.grid-main');
  const panelResizer = document.querySelector('#panel-resizer');
  const overlay = matchMedia('(max-width: 1100px)');
  let returnFocus = null;
  const status = createStatus();
  let selectedDN = '';
  const keyOf = (entry) => details ? entry.id : entry.dn;
  const sameKey = (left, right) => details ? left === right : sameDN(left, right);
  let started = false;
  let rootDN = '';
  let search = searchConfig === false || fetchEntries ? {} : linkedSearch();

  let columnKeys = columnSet.load();
  let contextualKeys = [];
  function applySearchColumns() {
    columnKeys = columnKeys.filter((key) => !contextualKeys.includes(key));
    contextualKeys = (search.options ?? []).flatMap((option) => searchConfig.columns?.[option] ?? []).filter((key) => !columnKeys.includes(key));
    columnKeys = [...new Set([...contextualKeys, ...columnKeys])];
  }
  applySearchColumns();
  let columns = columnSet.columns(columnKeys);
  let widths = columnSet.loadWidths();
  const fitted = new Map();
  const widthOf = (column) => widths[column.key] ?? fitted.get(column.key) ?? column.width;

  const cellText = (column, entry) => column.text(entry.record, entry) || '';

  let entries = [];
  let loadedProperties = [];
  let loadedOptions = {};
  let namingContexts = [];
  let rootsKnown = false;
  let visible = [];
  let rendered = 0;
  let sortKey = 'name';
  let sortDirection = 1;
  let controller;

  const headers = new Map();
  const columnFilters = new Map();
  const clearFilters = document.querySelector('#grid-clear-filters');
  const columnFilter = createColumnFilter({
    menu: document.querySelector('#column-filter'),
    onChange(key, state) {
      if (state) columnFilters.set(key, state); else columnFilters.delete(key);
      paintFilters();
      update();
    },
  });

  function filteredBy(entry, except) {
    return columns.every((column) => column.key === except || !columnFilters.has(column.key)
      || matchesFilter(filterSpec(column), columnFilters.get(column.key), entry));
  }

  function paintFilters() {
    for (const [key, th] of headers) {
      const trigger = th.querySelector('.column-filter-trigger');
      const active = isActive(columnFilters.get(key));
      trigger.classList.toggle('is-active', active);
      trigger.setAttribute('aria-label', `Filter ${th.dataset.label}${active ? ', filter active' : ''}`);
    }
    clearFilters.hidden = !columnFilters.size;
  }

  const filterKind = (list, key) => {
    const column = list.find((item) => item.key === key);
    return column ? filterSpec(column).type : null;
  };

  function reconcileFilters(previous) {
    for (const [key, state] of columnFilters) {
      if (filterKind(columns, key) !== state.type) columnFilters.delete(key);
    }
    const open = columnFilter.openKey();
    if (open && filterKind(columns, open) !== filterKind(previous, open)) columnFilter.close();
    paintFilters();
  }

  function resetFilters() {
    columnFilters.clear();
    paintFilters();
    update();
  }

  function revealFilteredOut() {
    if (!columnFilters.size) return;
    columnFilters.clear();
    paintFilters();
    notify.info(`Column filters cleared to show the new ${noun.singular}`);
  }

  function sizeColumns() {
    document.querySelector('#grid').style.setProperty('--columns-width', `${columns.reduce((total, column) => total + widthOf(column), 0)}px`);
  }

  const columnCells = (column, selector = '') => body.querySelectorAll(`tr[data-dn] > :nth-child(${columns.indexOf(column) + 2})${selector}`);
  const columnWidths = new ResizeObserver((observed) => {
    for (const { target } of observed) {
      const column = columns.find((item) => item.key === target.dataset.key);
      if (column) fitChips(columnCells(column, ' .cell-chips'));
    }
  });

  function setWidth(column, width) {
    widths[column.key] = Math.round(Math.min(MAX_COLUMN_WIDTH, Math.max(MIN_COLUMN_WIDTH, width)));
    headers.get(column.key).style.width = `${widths[column.key]}px`;
    sizeColumns();
  }

  function textRight(node, range) {
    range.selectNodeContents(node);
    return range.getBoundingClientRect().right;
  }

  function labelWidth(th) {
    const label = th.querySelector('.column-sort__label');
    const box = label.getBoundingClientRect();
    return Math.ceil(textRight(label, document.createRange()) - box.left + th.getBoundingClientRect().width - box.width);
  }

  function contentWidth(cell) {
    const box = cell.getBoundingClientRect();
    const style = getComputedStyle(cell);
    const range = document.createRange();
    const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    let right = box.left;
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (node.nodeType === Node.TEXT_NODE) right = Math.max(right, textRight(node, range));
      else if (getComputedStyle(node).display.startsWith('inline') || getComputedStyle(node.parentElement).display.endsWith('flex')) right = Math.max(right, node.getBoundingClientRect().right);
    }
    return Math.ceil(right - box.left + parseFloat(style.paddingRight) + parseFloat(style.borderRightWidth));
  }

  function fitLabels() {
    for (const column of columns) {
      if (widths[column.key]) continue;
      const th = headers.get(column.key);
      const required = labelWidth(th);
      if (required <= widthOf(column)) continue;
      fitted.set(column.key, required);
      th.style.width = `${required}px`;
    }
  }

  function fitColumn(column) {
    const th = headers.get(column.key);
    expandChips(columnCells(column, ' .cell-chips'));
    setWidth(column, Math.max(labelWidth(th), ...[...columnCells(column)].map(contentWidth)));
    fitChips(columnCells(column, ' .cell-chips'));
    columnSet.saveWidths(widths);
  }

  function resizeColumn(event, column, grip) {
    if (event.button !== 0) return;
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = headers.get(column.key).getBoundingClientRect().width;
    grip.setPointerCapture(event.pointerId);
    grip.classList.add('is-dragging');
    root.classList.add('is-resizing');
    const move = (moveEvent) => setWidth(column, startWidth + moveEvent.clientX - startX);
    const stop = () => {
      grip.classList.remove('is-dragging');
      root.classList.remove('is-resizing');
      grip.removeEventListener('pointermove', move);
      columnSet.saveWidths(widths);
    };
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', stop, { once: true });
    grip.addEventListener('pointercancel', stop, { once: true });
  }

  function buildHead() {
    const index = element('th', 'col-index');
    index.scope = 'col';
    index.append(element('span', 'visually-hidden', 'Row'));
    head.replaceChildren(index);
    headers.clear();
    columnWidths.disconnect();
    for (const column of columns) {
      const th = element('th', column.key === 'name' ? 'col-name' : '');
      th.scope = 'col';
      th.style.width = `${widthOf(column)}px`;
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
      const filterButton = button('', { iconName: 'filter', className: 'icon-button column-filter-trigger' });
      filterButton.setAttribute('aria-haspopup', 'dialog');
      filterButton.setAttribute('aria-controls', 'column-filter');
      filterButton.setAttribute('aria-expanded', 'false');
      filterButton.disabled = true;
      filterButton.addEventListener('pointerdown', (event) => columnFilter.pressed(filterButton, event));
      filterButton.addEventListener('click', () => columnFilter.open(filterButton, {
        column,
        entries: entries.filter((entry) => filteredBy(entry, column.key)),
        state: columnFilters.get(column.key),
      }));
      const grip = element('span', 'column-resizer');
      grip.setAttribute('aria-hidden', 'true');
      grip.addEventListener('pointerdown', (event) => resizeColumn(event, column, grip));
      grip.addEventListener('dblclick', () => fitColumn(column));
      th.dataset.label = column.label;
      th.append(control, filterButton, grip);
      head.append(th);
      headers.set(column.key, th);
      columnWidths.observe(th);
    }
    fitLabels();
    sizeColumns();
  }

  function setSortable(enabled) {
    for (const th of headers.values()) for (const control of th.querySelectorAll('button')) control.disabled = !enabled;
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
    tr.dataset.key = keyOf(entry);
    tr.setAttribute('aria-selected', String(sameKey(keyOf(entry), selectedDN)));
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
    const rows = next.map((entry, offset) => row(entry, rendered + offset));
    sentinel.remove();
    body.append(...rows);
    fitChips(rows.flatMap((tr) => [...tr.querySelectorAll('.cell-chips')]));
    rendered += next.length;
    if (rendered < visible.length) { body.append(sentinel); observer.observe(sentinel); }
  }

  function update() {
    const query = filter.value.trim().toLocaleLowerCase();
    const column = columns.find((item) => item.key === sortKey) ?? columnSet.name;
    const key = column.sort ? (entry) => column.sort(entry.record, entry) : (entry) => cellText(column, entry) || null;
    sentinelCell.colSpan = columns.length + 1;
    visible = entries
      .filter((entry) => (!query || columns.some((item) => cellText(item, entry).toLocaleLowerCase().includes(query))) && filteredBy(entry))
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
    const narrowed = query || columnFilters.size;
    count.textContent = narrowed ? `${visible.length} of ${entries.length} ${noun.plural}` : `${entries.length} ${entries.length === 1 ? noun.singular : noun.plural}`;
    message.replaceChildren();
    syncExport();
    if (entries.length && !visible.length) {
      if (columnFilters.size) showMessage(`No ${noun.plural} match`, 'No rows match the column filters.', resetFilters, 'Clear filters');
      else showMessage(`No ${noun.plural} match`, 'Try a different filter.');
    }
  }

  function showMessage(title, description, retry, actionLabel = 'Retry') {
    const box = element('div');
    box.append(element('h2', '', title), element('p', '', description));
    if (retry) {
      const action = button(actionLabel, { iconName: actionLabel === 'Retry' ? 'refresh' : 'close' });
      action.addEventListener('click', retry);
      box.append(action);
    }
    message.replaceChildren(box);
  }

  function syncExport() {
    exportButton.disabled = filter.disabled || !visible.length;
  }

  function exportCsv() {
    const header = details ? 'ObjectDN' : 'distinguishedName';
    const shown = columns.some((column) => column.label.toLowerCase() === header.toLowerCase());
    const fields = columns.map((column) => ({ label: column.label, value: (entry) => (column.csv ?? column.text)(entry.record, entry) }));
    if (!shown && visible.some((entry) => entry.dn)) fields.push({ label: header, value: (entry) => entry.dn });
    downloadCsv(exportName, toCsv(fields, visible));
    notify.success(`Exported ${visible.length} ${visible.length === 1 ? noun.singular : noun.plural} to CSV`);
  }

  async function load(fresh = false) {
    started = true;
    onLoadState?.(true);
    if (details) { closePanel(); entries = []; visible = []; }
    controller?.abort();
    controller = new AbortController();
    const { signal } = controller;
    filter.disabled = true;
    refresh.disabled = true;
    syncExport();
    setSortable(false);
    body.replaceChildren();
    const finishLoading = beginLoading(scroller, {
      signal,
      onDelay: () => body.replaceChildren(...skeletonRows(['col-index', ...columns.map((column) => column.key === 'name' ? 'col-name' : '')])),
    });
    message.replaceChildren();
    count.textContent = `Loading ${noun.plural}…`;
    try {
      const properties = columnSet.properties(columns);
      const options = columnSet.requestOptions(columns);
      const result = fetchEntries
        ? await fetchEntries({ signal, fresh })
        : await directory.list(endpoint, { signal, fresh, properties, search, options });
      if (signal.aborted) return false;
      entries = result;
      loadedProperties = properties;
      loadedOptions = options;
      filter.disabled = false;
      setSortable(true);
      update();
      panel.refreshSummary();
      if (!entries.length) showMessage(emptyMessage?.title ?? `No ${noun.plural} found`, emptyMessage?.description ?? `The connected directory returned no ${noun.singular} objects.`);
      return true;
    } catch (error) {
      if (signal.aborted) return false;
      entries = [];
      visible = [];
      syncExport();
      body.replaceChildren();
      count.textContent = '';
      showMessage(`Cannot load ${noun.plural}`, error.message, () => load(true));
      return false;
    } finally {
      if (!signal.aborted) { finishLoading(); refresh.disabled = false; onLoadState?.(false); }
    }
  }

  function explorerURL(dn) {
    if (details) dn = entries.find((entry) => entry.id === dn)?.dn ?? '';
    const url = new URL(root.dataset.explorer, window.location.origin);
    url.searchParams.set('dn', dn);
    return url;
  }

  function remember(dn) {
    if (details) return;
    const url = new URL(window.location.href);
    if (dn) url.searchParams.set('dn', dn); else url.searchParams.delete('dn');
    history.replaceState(null, '', url);
  }

  function rememberSearch(value) {
    const url = new URL(window.location.href);
    if (value.filter) url.searchParams.set('ldapfilter', value.filter); else url.searchParams.delete('ldapfilter');
    history.replaceState(null, '', url);
  }

  function markSelected() {
    for (const tr of body.querySelectorAll('tr[data-dn]')) tr.setAttribute('aria-selected', String(sameKey(tr.dataset.key, selectedDN)));
  }

  function syncOverlay() {
    const covering = overlay.matches && !panelRoot.hidden;
    gridMain.inert = covering;
    for (const node of [document.querySelector('.grid-page > .toolbar'), document.querySelector('[data-grid-query]'), document.querySelector('.workspace > .sidebar')]) {
      if (node) node.inert = covering;
    }
    if (covering && !panelRoot.contains(document.activeElement)) {
      (panelRoot.querySelector('[role="tab"][aria-selected="true"]') ?? panelRoot.querySelector('#panel-close'))?.focus();
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
    explorerLink.hidden = Boolean(details && !entries.find((entry) => entry.id === dn)?.dn);
    panelRoot.hidden = false;
    panelResizer.hidden = false;
    syncOverlay();
    if (!details) discoverRoots();
    if (opening && overlay.matches) (panelRoot.querySelector('[role="tab"][aria-selected="true"]') ?? panelRoot.querySelector('#panel-close'))?.focus();
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
    const row = body.querySelector(`tr[data-key="${CSS.escape(previous)}"]`);
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

  function searchActive() {
    return Object.entries(search).some(([key, value]) => (Array.isArray(value) ? value.length : key === 'scope' ? value !== 'SUBTREE' : Boolean(value)));
  }

  async function reloadKeepingPosition() {
    const scrollTop = scroller.scrollTop;
    if (!(await load(true))) return;
    const position = visible.findIndex((entry) => sameKey(keyOf(entry), selectedDN));
    while (position >= rendered && rendered < visible.length) renderMore();
    scroller.scrollTop = scrollTop;
  }

  async function readEntry(dn) {
    if (!dn) return null;
    try {
      const properties = [...new Set([...loadedProperties, ...columnSet.properties(columns)])];
      const options = { ...loadedOptions, ...columnSet.requestOptions(columns) };
      const [entry] = await directory.list(endpoint, { fresh: true, properties, options, search: { base: dn, scope: 'BASE' } });
      return entry ?? null;
    } catch {
      return null;
    }
  }

  function reconcile(item) {
    if (!item) return;
    const updated = item.record ? item : entryFromRecord(item);
    const index = entries.findIndex((entry) => sameDN(entry.dn, updated.dn));
    if (index < 0) return;
    entries[index] = updated;
    const scrollTop = scroller.scrollTop;
    update();
    const position = visible.findIndex((entry) => sameKey(keyOf(entry), selectedDN));
    while (position >= rendered && rendered < visible.length) renderMore();
    scroller.scrollTop = scrollTop;
  }

  const guard = createMutationGuard({ onBlocked: () => notify.info('Wait for the current change to finish.') });
  const panel = details ? createRowDetails({ root: panelRoot, getEntry: (key) => entries.find((entry) => entry.id === key), details }) : createObjectPanel({
    root: panelRoot,
    summary: summary && { label: summary.label, render: (panel, record) => summary.render(panel, entries.find((entry) => sameDN(entry.dn, record.dn)), record) },
    directory,
    status,
    guard,
    scope: (dn) => namingContext(dn, [rootDN, ...namingContexts]) ?? rootDN,
    onNavigate: select,
    getRoots: async () => {
      await discoverRoots();
      return rootsKnown ? [rootDN, ...namingContexts] : [];
    },
    onMoved: async ({ movedTo }) => {
      selectedDN = movedTo;
      remember(movedTo);
      explorerLink.href = explorerURL(movedTo);
      await panel.open(movedTo, { fresh: true });
      await reloadKeepingPosition();
    },
    onSaved: async () => {
      const record = await panel.open(selectedDN, { fresh: true });
      if (fetchEntries || searchActive()) await reloadKeepingPosition();
      else reconcile((await readEntry(selectedDN)) ?? record);
    },
    onDeleted: deletable ? (record) => { removeEntry(record.dn); afterDelete?.(record); } : null,
    isRoot: (dn) => !rootsKnown || isProtected(dn) || [rootDN, ...namingContexts].some((root) => sameDN(root, dn)),
    extraActions: panelActions && ((record) => panelActions(record, entries.filter((entry) => sameDN(entry.dn, record.dn)))),
    describeRemoval: describeRemoval && ((record) => describeRemoval(record, entries.filter((entry) => sameDN(entry.dn, record.dn)))),
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
    if (tr) select(tr.dataset.key);
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
    else if (event.key === 'Enter') { event.preventDefault(); select(tr.dataset.key); return; }
    else return;
    event.preventDefault();
    if (!target?.dataset.key) return;
    tr.tabIndex = -1;
    target.tabIndex = 0;
    target.focus();
  });

  filter.addEventListener('input', update);
  filter.addEventListener('keydown', (event) => { if (event.key === 'Escape' && filter.value) { filter.value = ''; update(); } });
  refresh.addEventListener('click', () => load(true));
  exportButton.addEventListener('click', exportCsv);
  createActionMenu({ trigger: document.querySelector('#grid-more'), menu: document.querySelector('#more-menu') });

  (columnSet.objectClass ? directory.schemaAttributes(columnSet.objectClass) : Promise.resolve(null))
    .then((attributes) => {
      if (!attributes) return;
      columnSet.setSchema(attributes);
      fieldsMenu.schemaChanged();
      if (!columnKeys.some((key) => key.startsWith('attr:'))) return;
      const focusedHeader = document.activeElement?.closest('#grid-head th')?.dataset.key;
      const focusedRow = document.activeElement?.closest('#grid-body tr[data-dn]')?.dataset.key;
      const scrollTop = scroller.scrollTop;
      const scrollLeft = scroller.scrollLeft;
      const previous = columns;
      columns = columnSet.columns(columnKeys);
      buildHead();
      reconcileFilters(previous);
      if (!filter.disabled) { setSortable(true); update(); }
      scroller.scrollTop = scrollTop;
      scroller.scrollLeft = scrollLeft;
      if (focusedHeader) head.querySelector(`th[data-key="${CSS.escape(focusedHeader)}"] button`)?.focus({ preventScroll: true });
      else if (focusedRow) body.querySelector(`tr[data-key="${CSS.escape(focusedRow)}"]`)?.focus({ preventScroll: true });
    })
    .catch(() => {});

  let discovering = null;
  function discoverRoots() {
    if (rootsKnown) return Promise.resolve();
    discovering ??= Promise.all([domainReady, directory.server()])
      .then(([, server]) => {
        const contexts = server?.raw?.namingContexts ?? server?.namingContexts;
        if (!rootDN || !Array.isArray(contexts)) return;
        namingContexts = contexts.filter((dn) => typeof dn === 'string');
        rootsKnown = true;
        panel.refreshActions();
      })
      .catch(() => {})
      .finally(() => { discovering = null; });
    return discovering;
  }

  const domainReady = (details ? Promise.resolve(null) : directory.domain())
    .then((domain) => { rootDN = domain?.root_dn ?? ''; return rootDN; })
    .catch(() => '');

  if (!details) discoverRoots();
  const fieldsMenu = createFieldsMenu({
    trigger: document.querySelector('#grid-fields'),
    menu: document.querySelector('#fields-menu'),
    columnSet,
    getKeys: () => columnKeys,
    onApply(keys, { widthsReset = false } = {}) {
      if (widthsReset) {
        widths = {};
        columnSet.saveWidths(widths);
      }
      columnKeys = keys;
      columnSet.save(keys.filter((key) => !contextualKeys.includes(key)));
      const previous = columns;
      columns = columnSet.columns(keys);
      if (!columns.some((column) => column.key === sortKey)) { sortKey = 'name'; sortDirection = 1; }
      buildHead();
      reconcileFilters(previous);
      fieldsMenu.refresh();
      const loaded = new Set(loadedProperties.map((name) => name.toLowerCase()));
      const missingOptions = Object.entries(columnSet.requestOptions(columns)).some(([key, value]) => loadedOptions[key] !== value);
      const needsFetch = !fetchEntries && (missingOptions || columnSet.properties(columns).some((name) => !loaded.has(name.toLowerCase())));
      if (!started) showMessage(initialMessage?.title ?? 'Choose search options', initialMessage?.description ?? 'Run a search to load results.');
      else if (needsFetch || (filter.disabled && !fetchEntries)) load();
      else if (!filter.disabled) { setSortable(true); update(); }
    },
  });

  if (searchConfig === false) document.querySelector('#grid-search').hidden = true;
  else createSearchMenu({
    trigger: document.querySelector('#grid-search'),
    menu: document.querySelector('#search-menu'),
    defaultBase: () => rootDN,
    ...searchConfig,
    initial: search,
    onApply(value) {
      search = value;
      rememberSearch(value);
      const previous = columns;
      applySearchColumns();
      columns = columnSet.columns(columnKeys);
      if (!columns.some((column) => column.key === sortKey)) { sortKey = 'name'; sortDirection = 1; }
      buildHead();
      reconcileFilters(previous);
      fieldsMenu.refresh();
      load(true);
    },
  });

  clearFilters.addEventListener('click', resetFilters);
  document.fonts?.ready.then(() => fitChips(body.querySelectorAll('.cell-chips')));
  buildHead();
  paintFilters();
  if (autoLoad) load().then((loaded) => {
    const requested = new URLSearchParams(window.location.search).get('dn');
    if (loaded && requested) select(requested);
  });
  else {
    refresh.disabled = true;
    showMessage(initialMessage?.title ?? 'Choose search options', initialMessage?.description ?? 'Run a search to load results.');
  }

  return {
    directory,
    status,
    domainReady,
    rootDN: () => rootDN,
    visibleEntries: () => [...visible],
    cancel() {
      controller?.abort();
      entries = [];
      visible = [];
      body.replaceChildren();
      count.textContent = '';
      filter.disabled = true;
      refresh.disabled = false;
      syncExport();
      setSortable(false);
      showMessage('Search cancelled', 'An LDAP read already started may finish on the server.');
      onLoadState?.(false);
    },
    reload: (fresh = false) => load(fresh),
    rerender() {
      if (!filter.disabled) update();
      panel.refreshSummary();
    },
    closeDetails() {
      if (!panel.canLeave()) return false;
      closePanel();
      return true;
    },
    async reloadAndFind(text) {
      if (!(await load(true))) return false;
      revealFilteredOut();
      filter.value = text;
      update();
      return true;
    },
    async showCreated(dn, text) {
      if (searchActive() || filter.disabled) return this.reloadAndFind(text);
      try {
        const properties = [...new Set([...loadedProperties, ...columnSet.properties(columns)])];
        const options = { ...loadedOptions, ...columnSet.requestOptions(columns) };
        const [created] = await directory.list(endpoint, { fresh: true, properties, options, search: { base: dn, scope: 'BASE' } });
        if (!created) return this.reloadAndFind(text);
        entries = [...entries.filter((entry) => !sameDN(entry.dn, created.dn)), created];
        revealFilteredOut();
        filter.value = text;
        update();
        return true;
      } catch {
        return this.reloadAndFind(text);
      }
    },
  };
}
