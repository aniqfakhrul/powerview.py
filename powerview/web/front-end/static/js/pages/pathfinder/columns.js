import { createColumnSet, nameColumn, textColumn, pill } from '../../components/grid/columns.js';

const field = textColumn;
const name = nameColumn('object');
const target = { ...name, label: 'Target', hint: 'Object whose ACL contains this ACE', attributes: ['ObjectDN'] };
target.render = (record, entry) => {
  const cell = name.render(record, entry);
  cell.title = entry.dn;
  return cell;
};
export const aceTypeTone = (type) => {
  const value = String(type ?? '');
  return value.includes('DENIED') ? 'danger' : value.includes('ALLOWED') ? 'success' : 'neutral';
};
const aceType = field('type', 'ACEType', 'ACE type', 240);
aceType.render = (record) => pill(record.attributes.ACEType, aceTypeTone(record.attributes.ACEType));

export const aclColumns = createColumnSet({
  storageKey: 'powerview.pathfinder.columns',
  name: target,
  allowCustom: false,
  catalog: [
    field('trustee', 'SecurityIdentifier', 'Trustee / membership chain', 290),
    field('via', 'GrantedVia', 'Group that grants this ACE to the principal, or Direct', 200),
    aceType,
    field('rights', 'Rights', 'Rights', 220),
    field('objectType', 'ObjectAceType', 'Object-specific right', 240),
    field('scope', 'Scope', 'Explicit or inherited ACE', 110),
    field('inheritance', 'InheritanceType', 'Inherited object type', 220),
    field('flags', 'ACEFlags', 'ACE flags', 220),
    field('dn', 'ObjectDN', 'Target DN', 360),
    field('sid', 'ObjectSID', 'Target SID', 240),
    field('mask', 'AccessMask', 'Access mask', 220),
    field('objectFlags', 'ObjectAceFlags', 'Object ACE flags', 240),
    field('debug', 'DEBUG', 'Parser note', 300),
  ],
  defaults: ['trustee', 'type', 'rights', 'objectType', 'scope'],
});
