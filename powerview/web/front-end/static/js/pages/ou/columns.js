import { attribute, values } from '../../core/directory.js';
import { parentDN } from '../../core/dn.js';
import { linkState, parseGpLink } from '../../core/gplink.js';
import { createColumnSet, dnColumn, nameColumn, textColumn, timeColumn } from '../../components/grid/columns.js';

let gpoNames = new Map();

export function setGpoNames(names) {
  gpoNames = names;
}

export function gpoLinks(record) {
  return parseGpLink(attribute(record, 'gPLink')).map((link) => ({ ...link, name: gpoNames.get(link.guid.toLowerCase()) || link.guid }));
}

const linkText = (link) => {
  const states = linkState(link);
  return states.length ? `${link.name} (${states.join(', ')})` : link.name;
};

export const inheritanceBlocked = (record) => (Number(values(attribute(record, 'gPOptions'))[0]) & 1) === 1;

const gpoColumn = {
  key: 'gpos', label: 'Linked GPOs', hint: 'From gPLink, with enforced and disabled links marked', icon: 'policy', width: 320, attributes: ['gPLink'],
  text: (record) => gpoLinks(record).map(linkText).join('; '),
  sort: (record) => gpoLinks(record).length,
  filter: {
    type: 'values',
    values: (record) => gpoLinks(record).map((link) => link.guid.toLowerCase()),
    label: (guid) => gpoNames.get(guid) || guid.toUpperCase(),
  },
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
