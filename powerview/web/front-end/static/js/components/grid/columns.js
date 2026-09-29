import { attribute, textValue, values } from '../../core/directory.js';
import { accountDisabled, formatTime, toTime } from '../../core/ldap-values.js';
import { element, icon } from '../../core/dom.js';

const ATTRIBUTE_NAME = /^[a-z][a-z0-9-]*$/i;

export const isAttributeName = (name) => ATTRIBUTE_NAME.test(name);
export const literalLabel = (column) => column.attributes.some((name) => column.label === name || column.label === `${name} (count)`);

const listed = (name) => (record) => values(attribute(record, name)).map((item) => (typeof item === 'object' ? JSON.stringify(item) : String(item))).filter(Boolean);

export const textColumn = (key, name, hint, width = 200, iconName = 'field-text') => ({
  key, label: name, hint, icon: iconName, width, attributes: [name],
  text: (record) => textValue(attribute(record, name)),
  filter: { type: 'values', values: listed(name) },
});

export const dnColumn = (key, name, hint, width = 260) => ({
  key, label: name, hint, icon: 'field-text', width, attributes: [name],
  text: (record) => textValue(attribute(record, name)),
  filter: { type: 'values', values: listed(name) },
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
  filter: { type: 'date', value: (record) => toTime(attribute(record, name)) },
});

function rangedValues(record, name) {
  const lower = name.toLowerCase();
  const keys = Object.keys(record.attributes).filter((key) => {
    const candidate = key.toLowerCase();
    return candidate === lower || candidate.startsWith(`${lower};range=`);
  });
  return {
    items: keys.flatMap((key) => values(record.attributes[key])),
    partial: keys.some((key) => /;range=\d+-\d+$/i.test(key)),
  };
}

export const countColumn = (key, name, hint) => ({
  key, label: `${name} (count)`, hint, icon: 'field-class', width: 130, attributes: [name],
  text: (record) => {
    const { items, partial } = rangedValues(record, name);
    return partial ? `${items.length}+` : String(items.length);
  },
  render: (record) => {
    const { items, partial } = rangedValues(record, name);
    const cell = element('span', partial ? 'cell-partial' : '', partial ? `${items.length}+` : String(items.length));
    if (partial) cell.title = `The directory returned the first ${items.length} values; the full count is larger.`;
    return cell;
  },
  sort: (record) => rangedValues(record, name).items.length,
  filter: { type: 'number', value: (record) => rangedValues(record, name).items.length },
});

export const pill = (text, tone = 'neutral') => (text ? element('span', `state state--${tone}`, text) : element('span', 'cell-muted', '—'));

export function chips(value) {
  const items = values(value).map(String).filter(Boolean);
  if (!items.length) return element('span', 'cell-muted', '—');
  const cell = element('span', 'cell-chips');
  cell.title = items.join(', ');
  cell.append(...items.map((item) => pill(item)));
  return cell;
}

export function booleanColumn(key, name, hint) {
  const flag = (record) => values(attribute(record, name))[0];
  return {
    key, label: name, hint, icon: 'field-class', width: 150, attributes: [name],
    text: (record) => (flag(record) === true ? 'Yes' : flag(record) === false ? 'No' : ''),
    filter: { type: 'values', choices: ['Yes', 'No'] },
    sort: (record) => (typeof flag(record) === 'boolean' ? Number(flag(record)) : null),
  };
}

const disabled = (record) => accountDisabled(attribute(record, 'userAccountControl'));

export const statusColumn = {
  key: 'status', label: 'Status', hint: 'From userAccountControl', icon: 'field-class', width: 110, attributes: ['userAccountControl'],
  render: (record) => element('span', disabled(record) ? 'state state--disabled' : 'state', disabled(record) ? 'Disabled' : 'Enabled'),
  text: (record) => (disabled(record) ? 'Disabled' : 'Enabled'),
  sort: (record) => Number(disabled(record)),
  filter: { type: 'values', choices: ['Enabled', 'Disabled'] },
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

function numberValue(record, name) {
  const raw = values(attribute(record, name))[0];
  const value = raw == null || raw === '' ? NaN : Number(raw);
  return Number.isFinite(value) ? value : null;
}

const numberColumn = (key, name, hint) => ({
  ...textColumn(key, name, hint),
  sort: (record) => numberValue(record, name),
  filter: { type: 'number', value: (record) => numberValue(record, name) },
});

const KIND_COLUMNS = { time: timeColumn, dn: dnColumn, integer: numberColumn };

export function customColumn(name, kind = 'text', key = `attr:${name}`) {
  const hint = kind === 'text' ? 'Custom attribute' : `Custom ${kind} attribute`;
  return { ...(KIND_COLUMNS[kind] ?? textColumn)(key, name, hint), custom: true };
}

export function createColumnSet({ storageKey, objectClass, name, catalog, defaults, allowCustom = true }) {
  let schema = null;

  function columnFor(key) {
    if (!key.startsWith('attr:')) return catalog.find((column) => column.key === key) ?? null;
    if (!allowCustom) return null;
    const attributeName = key.slice(5);
    if (!isAttributeName(attributeName)) return null;
    const known = schema?.get(attributeName.toLowerCase());
    return customColumn(known?.name ?? attributeName, known?.kind, key);
  }

  return {
    name,
    catalog,
    defaults,
    objectClass,
    allowCustom,
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
    loadWidths() {
      try {
        const saved = JSON.parse(localStorage.getItem(`${storageKey}.widths`));
        if (saved && typeof saved === 'object') return Object.fromEntries(Object.entries(saved).filter(([, width]) => Number.isFinite(width)));
      } catch { /* per-viewer convenience only */ }
      return {};
    },
    saveWidths(widths) {
      try { localStorage.setItem(`${storageKey}.widths`, JSON.stringify(widths)); } catch { /* per-viewer convenience only */ }
    },
    columns: (keys) => [name, ...keys.map(columnFor).filter(Boolean)],
    properties: (columns) => [...new Set(['name', ...columns.flatMap((column) => column.attributes)])],
    requestOptions: (columns) => Object.assign({}, ...columns.map((column) => column.request ?? {})),
  };
}
