import { attribute, values } from '../../core/directory.js';
import { parentDN } from '../../core/dn.js';
import { createColumnSet, dnColumn, nameColumn, textColumn, timeColumn } from '../../components/grid/columns.js';

const LINK = /\[LDAP:\/\/cn=(\{[0-9a-f-]+\})[^;\]]*;(\d+)\]/gi;
let gpoNames = new Map();

export function setGpoNames(names) {
  gpoNames = names;
}

export function gpoLinks(record) {
  const raw = values(attribute(record, 'gPLink')).join('');
  return [...raw.matchAll(LINK)].map(([, guid, flags]) => ({
    guid,
    name: gpoNames.get(guid.toLowerCase()) || guid,
    disabled: (Number(flags) & 1) !== 0,
    enforced: (Number(flags) & 2) !== 0,
  }));
}

const linkText = (link) => {
  const states = [link.enforced && 'enforced', link.disabled && 'disabled'].filter(Boolean);
  return states.length ? `${link.name} (${states.join(', ')})` : link.name;
};

export const inheritanceBlocked = (record) => (Number(values(attribute(record, 'gPOptions'))[0]) & 1) === 1;

const gpoColumn = {
  key: 'gpos', label: 'Linked GPOs', hint: 'From gPLink, with enforced and disabled links marked', icon: 'policy', width: 320, attributes: ['gPLink'],
  text: (record) => gpoLinks(record).map(linkText).join('; '),
  sort: (record) => gpoLinks(record).length,
  filter: { type: 'values', values: (record) => gpoLinks(record).map((link) => link.name) },
};

const inheritanceColumn = {
  key: 'inheritance', label: 'Inheritance', hint: 'From gPOptions', icon: 'field-class', width: 120, attributes: ['gPOptions'],
  text: (record) => (inheritanceBlocked(record) ? 'Blocked' : 'Inherited'),
  sort: (record) => Number(inheritanceBlocked(record)),
  filter: { type: 'values', choices: ['Inherited', 'Blocked'] },
};

const parentColumn = {
  key: 'parent', label: 'Parent', hint: 'Container holding this OU', icon: 'field-text', width: 300, attributes: [],
  text: (record) => parentDN(record.dn),
};

export const ouColumns = createColumnSet({
  storageKey: 'powerview.ou.columns',
  objectClass: 'organizationalUnit',
  name: nameColumn('ou'),
  catalog: [
    parentColumn,
    textColumn('description', 'description', 'Description', 300, 'field-desc'),
    gpoColumn,
    inheritanceColumn,
    dnColumn('managedBy', 'managedBy', 'Managed by'),
    timeColumn('created', 'whenCreated', 'Created'),
    timeColumn('modified', 'whenChanged', 'Modified'),
    textColumn('guid', 'objectGUID', 'Object GUID', 280),
  ],
  defaults: ['parent', 'description', 'gpos', 'inheritance', 'modified'],
});
