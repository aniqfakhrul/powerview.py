import { attribute, textValue, values } from '../../core/directory.js';
import { accountDisabled, formatTime, toTime } from '../../core/ldap-values.js';
import { element, icon } from '../../core/dom.js';

const ATTRIBUTE_NAME = /^[a-z][a-z0-9-]*$/i;

export const isAttributeName = (name) => ATTRIBUTE_NAME.test(name);

export const textColumn = (key, name, hint, width = 200, iconName = 'field-text') => ({
  key, label: name, hint, icon: iconName, width, attributes: [name],
  text: (record) => textValue(attribute(record, name)),
});

export const dnColumn = (key, name, hint, width = 260) => ({
  key, label: name, hint, icon: 'field-text', width, attributes: [name],
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

export const timeColumn = (key, name, hint) => ({
  key, label: name, hint, icon: 'field-date', width: 190, attributes: [name],
  text: (record) => formatTime(toTime(attribute(record, name))),
  sort: (record) => toTime(attribute(record, name)),
});

export const countColumn = (key, name, hint) => ({
  key, label: `${name} (count)`, hint, icon: 'field-class', width: 130, attributes: [name],
  text: (record) => String(values(attribute(record, name)).length),
  sort: (record) => values(attribute(record, name)).length,
});

const disabled = (record) => accountDisabled(attribute(record, 'userAccountControl'));

export const statusColumn = {
  key: 'status', label: 'Status', hint: 'From userAccountControl', icon: 'field-class', width: 110, attributes: ['userAccountControl'],
  render: (record) => element('span', disabled(record) ? 'state state--disabled' : 'state', disabled(record) ? 'Disabled' : 'Enabled'),
  text: (record) => (disabled(record) ? 'Disabled' : 'Enabled'),
  sort: (record) => Number(disabled(record)),
};

export function nameColumn(iconName) {
  return {
    key: 'name', label: 'name', hint: 'Object name', icon: 'field-text', width: 240, attributes: ['name'],
    render: (record, entry) => {
      const cell = element('div', 'cell-name');
      cell.append(icon(iconName, `type--${iconName}`), element('span', '', entry.name));
      return cell;
    },
    text: (record, entry) => entry.name,
  };
}

const numberColumn = (key, name, hint) => ({
  ...textColumn(key, name, hint),
  sort: (record) => {
    const value = Number(values(attribute(record, name))[0]);
    return Number.isFinite(value) ? value : null;
  },
});

const KIND_COLUMNS = { time: timeColumn, dn: dnColumn, integer: numberColumn };

export function customColumn(name, kind = 'text') {
  const hint = kind === 'text' ? 'Custom attribute' : `Custom ${kind} attribute`;
  return { ...(KIND_COLUMNS[kind] ?? textColumn)(`attr:${name}`, name, hint), custom: true };
}

export function createColumnSet({ storageKey, objectClass, name, catalog, defaults }) {
  let schema = null;

  function columnFor(key) {
    if (!key.startsWith('attr:')) return catalog.find((column) => column.key === key) ?? null;
    const attributeName = key.slice(5);
    if (!isAttributeName(attributeName)) return null;
    const known = schema?.get(attributeName.toLowerCase());
    return customColumn(known?.name ?? attributeName, known?.kind);
  }

  return {
    name,
    catalog,
    defaults,
    objectClass,
    columnFor,
    setSchema(attributes) {
      schema = new Map(attributes.map((item) => [item.name.toLowerCase(), item]));
    },
    schemaAttribute: (attributeName) => schema?.get(attributeName.toLowerCase()) ?? null,
    schemaAttributes: () => (schema ? [...schema.values()] : null),
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
