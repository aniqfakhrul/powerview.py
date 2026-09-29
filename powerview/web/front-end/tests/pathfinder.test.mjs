import test from 'node:test';
import assert from 'node:assert/strict';
import { aclEntries } from '../static/js/pages/pathfinder/records.js';

test('ACL rows preserve evidence and distinguish ACEs on the same target', () => {
  const ace = { ObjectDN: 'CN=Alice,DC=example,DC=test', ACEType: 'ACCESS_ALLOWED_ACE', SecurityIdentifier: '(Helpdesk) -> Alice', AccessMask: '0x100' };
  const source = [{ attributes: [ace, { ...ace, ACEType: 'ACCESS_DENIED_OBJECT_ACE' }] }];
  const rows = aclEntries(source);
  assert.equal(rows[0].name, 'Alice');
  assert.notEqual(rows[0].id, rows[1].id);
  assert.equal(rows[0].record.attributes.SecurityIdentifier, ace.SecurityIdentifier);
  assert.equal(rows[0].record.attributes.Rights, '0x100');
  assert.equal(rows[1].record.attributes.Effect, 'Deny');
  assert.equal(ace.Effect, undefined);
});

test('empty results remain distinct from missing or malformed results', () => {
  assert.deepEqual(aclEntries([]), []);
  for (const result of [null, {}, [{ attributes: {} }], [{ attributes: [null] }]]) assert.throws(() => aclEntries(result));
  assert.equal(aclEntries([{ attributes: [{}] }])[0].record.attributes.Effect, 'Unsupported');
});
