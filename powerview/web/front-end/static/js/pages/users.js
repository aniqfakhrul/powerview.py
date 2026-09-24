import { createDirectory, userFromRecord } from '../core/directory.js';
import { button, element, icon } from '../core/dom.js';
import { namingContext, sameDN } from '../core/dn.js';
import { createMutationGuard } from '../core/mutation-guard.js';
import { createObjectPanel } from '../components/object-panel/index.js';
import { createResizer } from '../components/resizer.js';
import { createStatus } from '../components/status.js';
import { createNewUser } from './users/new-user.js';
import { NAME_COLUMN, columnFor, loadKeys, propertiesFor, saveKeys } from './users/columns.js';
import { createFieldsMenu } from './users/fields-menu.js';

const PAGE_SIZE = 200;
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

const root = document.querySelector('#users');
const directory = createDirectory(new URL(root.dataset.apiRoot, window.location.origin));
const scroller = document.querySelector('#grid-scroll');
const head = document.querySelector('#grid-head');
const body = document.querySelector('#grid-body');
const message = document.querySelector('#grid-message');
const count = document.querySelector('#grid-count');
const filter = document.querySelector('#grid-filter');
const refresh = document.querySelector('#grid-refresh');
const newButton = document.querySelector('#user-new');
const panelRoot = document.querySelector('#object-panel');
const explorerLink = document.querySelector('#panel-explorer');
const gridMain = document.querySelector('.grid-main');
const panelResizer = document.querySelector('#panel-resizer');
const overlay = matchMedia('(max-width: 1100px)');
let returnFocus = null;
const status = createStatus();
let selectedDN = '';
let rootDN = '';


let columnKeys = loadKeys();
let columns = [NAME_COLUMN, ...columnKeys.map(columnFor)];

const cellText = (column, user) => column.text(user.record, user) || '';

let users = [];
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

function row(user, index) {
  const tr = element('tr');
  tr.tabIndex = index === 0 ? 0 : -1;
  tr.dataset.dn = user.dn;
  tr.setAttribute('aria-selected', String(sameDN(user.dn, selectedDN)));
  tr.setAttribute('aria-rowindex', String(index + 2));
  tr.append(element('td', 'col-index', String(index + 1)));
  for (const column of columns) {
    const td = element('td', column.key === 'name' ? 'col-name' : '');
    const value = cellText(column, user);
    if (column.render) td.append(column.render(user.record, user));
    else if (value) { td.textContent = value; td.title = value; }
    else td.append(element('span', 'cell-muted', '—'));
    tr.append(td);
  }
  return tr;
}

const sentinel = element('tr', 'grid-sentinel');
const sentinelCell = element('td');
sentinel.append(sentinelCell);
const observer = new IntersectionObserver((entries) => {
  if (entries.some((entry) => entry.isIntersecting)) renderMore();
}, { root: scroller, rootMargin: '400px' });

function renderMore() {
  const next = visible.slice(rendered, rendered + PAGE_SIZE);
  sentinel.remove();
  body.append(...next.map((user, offset) => row(user, rendered + offset)));
  rendered += next.length;
  if (rendered < visible.length) { body.append(sentinel); observer.observe(sentinel); }
}

function update() {
  const query = filter.value.trim().toLocaleLowerCase();
  const column = columns.find((item) => item.key === sortKey) ?? NAME_COLUMN;
  const key = column.sort ? (user) => column.sort(user.record, user) : (user) => cellText(column, user) || null;
  sentinelCell.colSpan = columns.length + 1;
  visible = users
    .filter((user) => !query || columns.some((item) => cellText(item, user).toLocaleLowerCase().includes(query)))
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
  count.textContent = query ? `${visible.length} of ${users.length} users` : `${users.length} ${users.length === 1 ? 'user' : 'users'}`;
  message.replaceChildren();
  if (users.length && !visible.length) showMessage('No users match', 'Try a different filter.');
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
  count.textContent = 'Loading users…';
  try {
    users = await directory.users({ signal, fresh, properties: propertiesFor(columns) });
    filter.disabled = false;
    setSortable(true);
    update();
    if (!users.length) showMessage('No users found', 'The connected directory returned no user objects.');
    return true;
  } catch (error) {
    if (signal.aborted) return false;
    users = [];
    body.replaceChildren();
    count.textContent = '';
    showMessage('Cannot load users', error.message, () => load(true));
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

function reconcile(record) {
  if (!record) return;
  const updated = userFromRecord(record);
  const index = users.findIndex((user) => sameDN(user.dn, updated.dn));
  if (index < 0) return;
  users[index] = updated;
  const scrollTop = scroller.scrollTop;
  update();
  const position = visible.findIndex((user) => sameDN(user.dn, selectedDN));
  while (position >= rendered && rendered < visible.length) renderMore();
  scroller.scrollTop = scrollTop;
}

const guard = createMutationGuard({ onBlocked: () => status.info('Wait for the current change to finish.') });
const panel = createObjectPanel({
  root: panelRoot,
  directory,
  status,
  guard,
  scope: (dn) => namingContext(dn, [rootDN]) ?? rootDN,
  onNavigate: select,
  onSaved: async () => reconcile(await panel.open(selectedDN, { fresh: true })),
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
  const tr = event.target.closest('tr[data-dn]');
  if (tr) select(tr.dataset.dn);
});

body.addEventListener('keydown', (event) => {
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

const newUser = createNewUser({
  directory,
  defaultContainer: () => `CN=Users,${rootDN}`,
  async onCreated(name) {
    status.success(`Created ${name}`);
    if (!(await load(true))) return;
    filter.value = name;
    update();
  },
});
newButton.addEventListener('click', () => newUser.open());

directory.domain()
  .then((domain) => { rootDN = domain?.root_dn ?? ''; newButton.disabled = !rootDN; })
  .catch(() => { newButton.title = 'Unavailable until the directory responds'; });
const fieldsMenu = createFieldsMenu({
  trigger: document.querySelector('#grid-fields'),
  menu: document.querySelector('#fields-menu'),
  getKeys: () => columnKeys,
  onApply(keys) {
    columnKeys = keys;
    saveKeys(keys);
    columns = [NAME_COLUMN, ...keys.map(columnFor).filter(Boolean)];
    if (!columns.some((column) => column.key === sortKey)) { sortKey = 'name'; sortDirection = 1; }
    buildHead();
    fieldsMenu.refresh();
    load();
  },
});

buildHead();
load().then((loaded) => {
  const requested = new URLSearchParams(window.location.search).get('dn');
  if (loaded && requested) select(requested);
});
