import { createAPI, APIError } from '../core/api.js';
import { attribute, textValue, values } from '../core/directory.js';
import { dnLabel } from '../core/dn.js';
import { button, element, icon } from '../core/dom.js';

const PAGE_SIZE = 200;
const ACCOUNT_DISABLED = 0x2;
const PROPERTIES = ['name', 'sAMAccountName', 'userAccountControl', 'description', 'mail', 'lastLogonTimestamp', 'whenCreated'];
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

const root = document.querySelector('#users');
const request = createAPI(new URL(root.dataset.apiRoot, window.location.origin));
const scroller = document.querySelector('#grid-scroll');
const head = document.querySelector('#grid-head');
const body = document.querySelector('#grid-body');
const message = document.querySelector('#grid-message');
const count = document.querySelector('#grid-count');
const filter = document.querySelector('#grid-filter');
const refresh = document.querySelector('#grid-refresh');

const text = (record, name) => textValue(attribute(record, name));
const timestamp = (value) => { const time = Date.parse(value); return Number.isNaN(time) ? 0 : time; };
const disabled = (record) => (Number(values(attribute(record, 'userAccountControl'))[0]) & ACCOUNT_DISABLED) !== 0;

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
  { key: 'lastLogon', label: 'Last logon', icon: 'field-date', width: 200, sort: (user) => timestamp(user.lastLogon) },
  { key: 'created', label: 'Created', icon: 'field-date', width: 200, sort: (user) => timestamp(user.created) },
];

let users = [];
let visible = [];
let rendered = 0;
let sortKey = 'name';
let sortDirection = 1;
let controller;

function toUser(record) {
  return {
    dn: record.dn,
    name: text(record, 'name') || dnLabel(record.dn),
    account: text(record, 'sAMAccountName'),
    disabled: disabled(record),
    description: text(record, 'description'),
    mail: text(record, 'mail'),
    lastLogon: text(record, 'lastLogonTimestamp'),
    created: text(record, 'whenCreated'),
  };
}

function renderHead() {
  head.replaceChildren(Object.assign(element('th', 'col-index'), { scope: 'col' }));
  head.firstChild.append(element('span', 'visually-hidden', 'Row'));
  for (const column of COLUMNS) {
    const th = element('th', column.key === 'name' ? 'col-name' : '');
    th.scope = 'col';
    th.style.width = `${column.width}px`;
    if (column.key === sortKey) th.setAttribute('aria-sort', sortDirection > 0 ? 'ascending' : 'descending');
    const control = button('', { className: 'column-sort' });
    control.append(icon(column.icon), element('span', 'column-sort__label', column.label), icon('chevron-right', 'column-sort__direction'));
    control.addEventListener('click', () => {
      sortDirection = sortKey === column.key ? -sortDirection : 1;
      sortKey = column.key;
      update();
    });
    th.append(control);
    head.append(th);
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
    const value = user[column.key];
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
      return sortDirection * (typeof left === 'number' ? left - right : collator.compare(left, right));
    });
  renderHead();
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
  renderHead();
  skeleton();
  message.replaceChildren();
  count.textContent = 'Loading users…';
  try {
    const data = await request('get/domainuser', { signal, body: { properties: PROPERTIES, no_cache: fresh } });
    if (!Array.isArray(data)) throw new APIError('The directory returned an unexpected user list. Check the CLI logs.');
    users = data.filter((item) => item && typeof item.dn === 'string' && item.attributes).map(toUser);
    filter.disabled = false;
    update();
    if (!users.length) showMessage('No users found', 'The connected directory returned no user objects.');
  } catch (error) {
    if (signal.aborted) return;
    body.replaceChildren();
    count.textContent = '';
    showMessage('Cannot load users', error.message, () => load(true));
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
  else if (event.key === 'End') target = body.querySelector('tr[data-dn]:last-of-type');
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
load();
