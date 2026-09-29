import test from 'node:test';
import assert from 'node:assert/strict';
import { objectType, TYPE_ICONS } from '../static/js/core/directory.js';
import { aclEntries } from '../static/js/pages/pathfinder/records.js';

test('ACL rows preserve evidence and distinguish ACEs on the same target', () => {
  const ace = { ObjectDN: 'CN=Alice,DC=example,DC=test', ACEType: 'ACCESS_ALLOWED_ACE', SecurityIdentifier: '(Helpdesk) -> Alice', AccessMask: ['ReadProperty', 'WriteProperty'] };
  const source = [{ attributes: [ace, { ...ace, ACEType: 'ACCESS_DENIED_OBJECT_ACE' }] }];
  const rows = aclEntries(source);
  assert.equal(rows[0].name, 'Alice');
  assert.notEqual(rows[0].id, rows[1].id);
  assert.equal(rows[0].record.attributes.SecurityIdentifier, ace.SecurityIdentifier);
  assert.deepEqual(rows[0].record.attributes.Rights, ['ReadProperty', 'WriteProperty']);
  assert.equal(rows[1].record.attributes.ACEType, 'ACCESS_DENIED_OBJECT_ACE');
  assert.equal(ace.Rights, undefined);
});

test('empty results remain distinct from missing or malformed results', () => {
  assert.deepEqual(aclEntries([]), []);
  for (const result of [null, {}, [{ attributes: {} }], [{ attributes: [null] }]]) assert.throws(() => aclEntries(result));
  assert.deepEqual(aclEntries([{ attributes: [{}] }])[0].record.attributes.Rights, []);
});

test('scope reflects the inherited ACE flag', () => {
  const [inherited, explicit] = aclEntries([{ attributes: [{ ACEFlags: ['CONTAINER_INHERIT_ACE', 'INHERITED_ACE'] }, { ACEFlags: [] }] }]);
  assert.equal(inherited.record.attributes.Scope, 'Inherited');
  assert.equal(explicit.record.attributes.Scope, 'Explicit');
});

test('target icons follow LDAP classes with a generic fallback', () => {
  for (const [classes, expected] of [
    [['top', 'user', 'computer'], 'computer'], [['USER'], 'user'], [['group'], 'group'],
    [['organizationalUnit'], 'ou'], [['groupPolicyContainer'], 'policy'],
    [['domainDNS'], 'domain'], [['container'], 'folder'], [undefined, 'object'],
  ]) {
    const [row] = aclEntries([{ objectClass: classes, attributes: [{ ObjectDN: 'CN=Target,DC=test' }] }]);
    assert.equal(TYPE_ICONS[objectType(row.record)], expected);
  }
});
