import { attribute, textValue, values } from '../../core/directory.js';
import { element, icon } from '../../core/dom.js';
import { createColumnSet, textColumn, timeColumn } from '../../components/grid/columns.js';
import { linkLabel, policyLinks } from './links.js';

const STATUS = ['All settings enabled', 'User settings disabled', 'Computer settings disabled', 'All settings disabled'];
const number = (record, name) => {
  const value = Number(values(attribute(record, name))[0]);
  return Number.isFinite(value) ? value : null;
};

export const policyName = (record) => textValue(attribute(record, 'displayName')) || textValue(attribute(record, 'name'));
export const policyStatus = (record) => STATUS[number(record, 'flags') ?? -1] ?? '';

const nameColumn = {
  key: 'name', label: 'displayName', hint: 'Policy name', icon: 'field-text', width: 280, attributes: ['displayName', 'name'],
  render: (record) => {
    const cell = element('div', 'cell-name');
    cell.append(icon('policy', 'type--policy'), element('span', '', policyName(record)));
    return cell;
  },
  text: policyName,
};

const versionColumn = (key, label, hint, shift) => ({
  key, label, hint, icon: 'field-class', width: 130, attributes: ['versionNumber'],
  text: (record) => (number(record, 'versionNumber') == null ? '' : String((number(record, 'versionNumber') >>> shift) & 0xffff)),
  sort: (record) => (number(record, 'versionNumber') == null ? null : (number(record, 'versionNumber') >>> shift) & 0xffff),
  filter: { type: 'number', value: (record) => (number(record, 'versionNumber') == null ? null : (number(record, 'versionNumber') >>> shift) & 0xffff) },
});

export const policyColumns = createColumnSet({
  storageKey: 'powerview.gpo.columns',
  objectClass: 'groupPolicyContainer',
  name: nameColumn,
  catalog: [
    {
      key: 'status', label: 'Status', hint: 'From flags', icon: 'field-class', width: 200, attributes: ['flags'],
      text: policyStatus,
      filter: { type: 'values', choices: STATUS },
    },
    {
      key: 'links', label: 'Linked to', hint: 'OUs and the domain linking this policy, from their gPLink', icon: 'ou', width: 300, attributes: [],
      text: (record) => policyLinks(record).map(linkLabel).join('; '),
      sort: (record) => policyLinks(record).length,
      filter: { type: 'values', values: (record) => policyLinks(record).map((link) => link.dn.toLowerCase()), label: (dn) => dn },
    },
    versionColumn('userVersion', 'User version', 'From versionNumber', 16),
    versionColumn('computerVersion', 'Computer version', 'From versionNumber', 0),
    timeColumn('modified', 'whenChanged', 'Modified'),
    timeColumn('created', 'whenCreated', 'Created'),
    textColumn('guid', 'name', 'Policy GUID', 300),
    textColumn('description', 'description', 'Description', 280, 'field-desc'),
    textColumn('path', 'gPCFileSysPath', 'SYSVOL path', 420),
    textColumn('machineExtensions', 'gPCMachineExtensionNames', 'Computer setting types', 320),
    textColumn('userExtensions', 'gPCUserExtensionNames', 'User setting types', 320),
  ],
  defaults: ['status', 'links', 'userVersion', 'computerVersion', 'modified'],
});
