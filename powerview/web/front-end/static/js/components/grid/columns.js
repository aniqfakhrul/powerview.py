import { attribute, textValue, values } from '../../core/directory.js';
import { accountDisabled, formatTime, toTime } from '../../core/ldap-values.js';
import { element, icon } from '../../core/dom.js';

const ATTRIBUTE_NAME = /^[a-z][a-z0-9-]*$/i;

export const isAttributeName = (name) => ATTRIBUTE_NAME.test(name);

export const textColumn = (key, label, name, width = 200, iconName = 'field-text') => ({
  key, label, icon: iconName, width, attributes: [name],
  text: (record) => textValue(attribute(record, name)),
});

export const dnColumn = (key, label, name, width = 260) => ({
  key, label, icon: 'field-text', width, attributes: [name],
  text: (record) => textValue(attribute(record, name)),
  render: (record) => {
    const dn = values(attribute(record, name)).find((item) => typeof item === 'string');
    if (!dn) return element('span', 'cell-muted', '—');
    const link = element('button', 'value value--dn cell-link', dn);
    link.type = 'button';
    link.title = dn;
    link.dataset.dnLink = dn;
    return link;
  },
});

export const timeColumn = (key, label, name) => ({
  key, label, icon: 'field-date', width: 190, attributes: [name],
  text: (record) => formatTime(toTime(attribute(record, name))),
  sort: (record) => toTime(attribute(record, name)),
});

export const countColumn = (key, label, name) => ({
  key, label, icon: 'field-class', width: 100, attributes: [name],
  text: (record) => String(values(attribute(record, name)).length),
  sort: (record) => values(attribute(record, name)).length,
});

const disabled = (record) => accountDisabled(attribute(record, 'userAccountControl'));

export const statusColumn = {
  key: 'status', label: 'Status', icon: 'field-class', width: 110, attributes: ['userAccountControl'],
  render: (record) => element('span', disabled(record) ? 'state state--disabled' : 'state', disabled(record) ? 'Disabled' : 'Enabled'),
  text: (record) => (disabled(record) ? 'Disabled' : 'Enabled'),
  sort: (record) => Number(disabled(record)),
};

export function nameColumn(iconName) {
  return {
    key: 'name', label: 'Name', icon: 'field-text', width: 240, attributes: ['name'],
    render: (record, entry) => {
      const cell = element('div', 'cell-name');
      cell.append(icon(iconName, `type--${iconName}`), element('span', '', entry.name));
      return cell;
    },
    text: (record, entry) => entry.name,
  };
}

export function customColumn(name) {
  return { ...textColumn(`attr:${name}`, name, name), custom: true };
}

export function createColumnSet({ storageKey, name, catalog, defaults }) {
  function columnFor(key) {
    if (key.startsWith('attr:')) return isAttributeName(key.slice(5)) ? customColumn(key.slice(5)) : null;
    return catalog.find((column) => column.key === key) ?? null;
  }

  return {
    name,
    catalog,
    defaults,
    columnFor,
    load() {
      try {
        const saved = JSON.parse(localStorage.getItem(storageKey));
        const keys = Array.isArray(saved) ? saved.filter((key) => typeof key === 'string' && columnFor(key)) : [];
        if (keys.length) return keys;
      } catch { /* per-viewer convenience only */ }
      return [...defaults];
    },
    save(keys) {
      try { localStorage.setItem(storageKey, JSON.stringify(keys)); } catch { /* per-viewer convenience only */ }
    },
    columns: (keys) => [name, ...keys.map(columnFor).filter(Boolean)],
    properties: (columns) => [...new Set(['name', ...columns.flatMap((column) => column.attributes)])],
  };
}
