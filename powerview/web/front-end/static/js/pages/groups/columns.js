import { attribute, textValue, values } from '../../core/directory.js';
import { dnChipColumn } from '../../components/grid/chips.js';
import { countColumn, createColumnSet, dnColumn, nameColumn, pill, textColumn, timeColumn } from '../../components/grid/columns.js';

const SCOPES = [[0x2, 'Global'], [0x4, 'Domain local'], [0x8, 'Universal']];
const SECURITY = 0x80000000;

function groupKind(record) {
  const raw = values(attribute(record, 'groupType'))[0];
  const numeric = Number(raw);
  if (!Number.isInteger(numeric)) return textValue(raw);
  const scope = SCOPES.find(([flag]) => (numeric & flag) !== 0)?.[1] ?? 'Unknown scope';
  return `${scope} ${(numeric >>> 0) & SECURITY ? 'security' : 'distribution'}`;
}

const typeColumn = {
  key: 'type', label: 'Type', hint: 'From groupType', icon: 'field-class', width: 190, attributes: ['groupType'],
  text: groupKind,
  render: (record) => pill(groupKind(record), /distribution$/.test(groupKind(record)) ? 'outline' : 'neutral'),
};

export const groupColumns = createColumnSet({
  storageKey: 'powerview.groups.columns',
  objectClass: 'group',
  name: nameColumn('group'),
  catalog: [
    textColumn('account', 'sAMAccountName', 'Account', 200),
    typeColumn,
    textColumn('description', 'description', 'Description', 320, 'field-desc'),
    countColumn('members', 'member', 'Members'),
    dnChipColumn('memberNames', 'member', 'Member names; hover a chip for its DN'),
    countColumn('memberOf', 'memberOf', 'Member of'),
    dnChipColumn('memberOfNames', 'memberOf', 'Group names; hover a chip for its DN'),
    textColumn('mail', 'mail', 'Email', 220),
    dnColumn('managedBy', 'managedBy', 'Managed by'),
    textColumn('adminCount', 'adminCount', 'Protected by AdminSDHolder', 120),
    timeColumn('created', 'whenCreated', 'Created'),
    timeColumn('modified', 'whenChanged', 'Modified'),
  ],
  defaults: ['account', 'type', 'description', 'members', 'created'],
});
