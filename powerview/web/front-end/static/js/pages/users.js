import { createDirectory } from '../core/directory.js';
import { button, element, icon } from '../core/dom.js';
import { createNewUser } from './users/new-user.js';

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
const status = document.querySelector('#status-message');
let rootDN = '';


function nameCell(user) {
  const cell = element('div', 'cell-name');
  cell.append(icon('user', 'type--user'), element('span', '', user.name));
  return cell;
}

function stateCell(user) {
  return element('span', user.disabled ? 'state state--disabled' : 'state', user.disabled ? 'Disabled' : 'Enabled');
}

const COLUMNS = [
  { key: 'name', label: 'Name', icon: 'field-text', width: 240, render: nameCell },
  { key: 'account', label: 'Account', icon: 'field-text', width: 180 },
  { key: 'status', label: 'Status', icon: 'field-class', width: 110, render: stateCell, sort: (user) => Number(user.disabled) },
  { key: 'description', label: 'Description', icon: 'field-desc', width: 320 },
  { key: 'mail', label: 'Email', icon: 'field-text', width: 240 },
  { key: 'lastLogon', label: 'Last logon', icon: 'field-date', width: 200, text: (user) => user.lastLogon.text, sort: (user) => user.lastLogon.time },
  { key: 'created', label: 'Created', icon: 'field-date', width: 200, text: (user) => user.created.text, sort: (user) => user.created.time },
];

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
  for (const column of COLUMNS) {
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
  tr.setAttribute('aria-rowindex', String(index + 2));
  tr.append(element('td', 'col-index', String(index + 1)));
  for (const column of COLUMNS) {
    const td = element('td', column.key === 'name' ? 'col-name' : '');
    const value = column.text ? column.text(user) : user[column.key];
    if (column.render) td.append(column.render(user));
    else if (value) { td.textContent = value; td.title = value; }
    else td.append(element('span', 'cell-muted', '—'));
    tr.append(td);
  }
  return tr;
}

const sentinel = element('tr', 'grid-sentinel');
sentinel.append(Object.assign(element('td'), { colSpan: COLUMNS.length + 1 }));
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
  const column = COLUMNS.find((item) => item.key === sortKey);
  const key = column.sort ?? ((user) => user[column.key]);
  visible = users
    .filter((user) => !query || [user.name, user.account, user.description, user.mail].some((value) => value.toLocaleLowerCase().includes(query)))
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
    for (const column of COLUMNS) tr.append(element('td', column.key === 'name' ? 'col-name' : ''));
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
    users = await directory.users({ signal, fresh });
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

function open(tr) {
  const url = new URL(root.dataset.explorer, window.location.origin);
  url.searchParams.set('dn', tr.dataset.dn);
  window.location.assign(url);
}

body.addEventListener('click', (event) => {
  const tr = event.target.closest('tr[data-dn]');
  if (tr) open(tr);
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
  else if (event.key === 'Enter') { open(tr); return; }
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
    status.textContent = `Created ${name}`;
    if (!(await load(true))) return;
    filter.value = name;
    update();
  },
});
newButton.addEventListener('click', () => newUser.open());

directory.domain()
  .then((domain) => { rootDN = domain?.root_dn ?? ''; newButton.disabled = !rootDN; })
  .catch(() => { newButton.title = 'Unavailable until the directory responds'; });
buildHead();
load();
