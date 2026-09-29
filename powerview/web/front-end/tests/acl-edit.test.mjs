import test from 'node:test';
import assert from 'node:assert/strict';
import { canEditACE } from '../static/js/components/object-panel/acl-edit.js';

const ace = {
  RemovalIdentity: { index: 0, ace: 'a'.repeat(64), dacl: 'b'.repeat(64) },
  ACEType: 'ACCESS_ALLOWED_OBJECT_ACE', ACEFlagsValue: 3, AccessMaskValue: 0x80000000,
};

test('editing is limited to explicit supported entries with complete numeric metadata', () => {
  assert.equal(canEditACE(ace), true);
  for (const changes of [
    { RemovalIdentity: null }, { ACEType: 'ACCESS_ALLOWED_CALLBACK_ACE' },
    { ACEFlagsValue: 16 }, { ACEFlagsValue: undefined }, { AccessMaskValue: '256' }, { AccessMaskValue: -1 }, { AccessMaskValue: 2 ** 32 },
  ]) assert.equal(canEditACE({ ...ace, ...changes }), false);
});
