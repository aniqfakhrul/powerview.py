import { attribute, textValue, values } from '../../core/directory.js';
import { accountDisabled, formatTime, toTime } from '../../core/ldap-values.js';
import { element, icon } from '../../core/dom.js';

const STORAGE_KEY = 'powerview.users.columns';
const ATTRIBUTE_NAME = /^[a-z][a-z0-9-]*$/i;

const text = (name) => (record) => textValue(attribute(record, name));
const time = (name) => ({
  attributes: [name],
  icon: 'field-date',
  width: 190,
  text: (record) => formatTime(toTime(attribute(record, name))),
  sort: (record) => toTime(attribute(record, name)),
});

function statusCell(record) {
  const disabled = accountDisabled(attribute(record, 'userAccountControl'));
  return element('span', disabled ? 'state state--disabled' : 'state', disabled ? 'Disabled' : 'Enabled');
}

export const NAME_COLUMN = {
  key: 'name', label: 'Name', icon: 'field-text', width: 240, attributes: ['name'],
  render: (record, user) => {
    const cell = element('div', 'cell-name');
    cell.append(icon('user', 'type--user'), element('span', '', user.name));
    return cell;
  },
  text: (record, user) => user.name,
};

export const CATALOG = [
  { key: 'account', label: 'Account', icon: 'field-text', width: 180, attributes: ['sAMAccountName'], text: text('sAMAccountName') },
  {
    key: 'status', label: 'Status', icon: 'field-class', width: 110, attributes: ['userAccountControl'], render: statusCell,
    text: (record) => (accountDisabled(attribute(record, 'userAccountControl')) ? 'Disabled' : 'Enabled'),
    sort: (record) => Number(accountDisabled(attribute(record, 'userAccountControl'))),
  },
  { key: 'description', label: 'Description', icon: 'field-desc', width: 320, attributes: ['description'], text: text('description') },
  { key: 'mail', label: 'Email', icon: 'field-text', width: 240, attributes: ['mail'], text: text('mail') },
  { key: 'displayName', label: 'Display name', icon: 'field-text', width: 220, attributes: ['displayName'], text: text('displayName') },
  { key: 'upn', label: 'User principal name', icon: 'field-text', width: 260, attributes: ['userPrincipalName'], text: text('userPrincipalName') },
  { key: 'title', label: 'Title', icon: 'field-text', width: 200, attributes: ['title'], text: text('title') },
  { key: 'department', label: 'Department', icon: 'field-text', width: 180, attributes: ['department'], text: text('department') },
  { key: 'groups', label: 'Groups', icon: 'field-class', width: 100, attributes: ['memberOf'], text: (record) => String(values(attribute(record, 'memberOf')).length), sort: (record) => values(attribute(record, 'memberOf')).length },
  { key: 'lastLogon', label: 'Last logon', ...time('lastLogonTimestamp') },
  { key: 'pwdLastSet', label: 'Password last set', ...time('pwdLastSet') },
  { key: 'created', label: 'Created', ...time('whenCreated') },
  { key: 'modified', label: 'Modified', ...time('whenChanged') },
];

export const DEFAULT_KEYS = ['account', 'status', 'description', 'mail', 'lastLogon', 'created'];

export function customColumn(name) {
  return { key: `attr:${name}`, label: name, icon: 'field-text', width: 200, attributes: [name], text: text(name), custom: true };
}

export function columnFor(key) {
  if (key.startsWith('attr:')) {
    const name = key.slice(5);
    return ATTRIBUTE_NAME.test(name) ? customColumn(name) : null;
  }
  return CATALOG.find((column) => column.key === key) ?? null;
}

export const isAttributeName = (name) => ATTRIBUTE_NAME.test(name);

export function loadKeys() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (Array.isArray(saved)) {
      const keys = saved.filter((key) => typeof key === 'string' && columnFor(key));
      if (keys.length) return keys;
    }
  } catch { /* per-viewer convenience only */ }
  return [...DEFAULT_KEYS];
}

export function saveKeys(keys) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(keys)); } catch { /* per-viewer convenience only */ }
}

export function propertiesFor(columns) {
  return [...new Set(['name', ...columns.flatMap((column) => column.attributes)])];
}
