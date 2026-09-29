import test from 'node:test';
import assert from 'node:assert/strict';
import { removalParameters } from '../static/js/components/object-panel/acl-removal.js';

const ace = { ACEType: 'ACCESS_ALLOWED_ACE', RawSecurityIdentifier: 'S-1-5-11', ACEFlagsValue: 0, AccessMaskValue: 0xf01ff };

test('ACL row removal preserves raw trustee, effect and inheritance', () => {
  assert.deepEqual(removalParameters({ ...ace, ACEType: 'ACCESS_DENIED_ACE', ACEFlagsValue: 3 }), {
    principalidentity: 'S-1-5-11', rights: 'fullcontrol', ace_type: 'denied', inheritance: true,
  });
});

test('object ACE removal targets one GUID, including individual DCSync rights', () => {
  const guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2';
  const object = { ...ace, ACEType: 'ACCESS_ALLOWED_OBJECT_ACE', ObjectAceFlagsValue: 1, ObjectAceTypeGuid: guid, AccessMaskValue: 256 };
  assert.equal(removalParameters(object).rights_guid, guid);
  assert.equal(removalParameters({ ...object, ObjectAceTypeGuid: 'bf9679c0-0de6-11d0-a285-00aa003049e2', AccessMaskValue: 48 }).rights_guid, 'bf9679c0-0de6-11d0-a285-00aa003049e2');
  for (const changed of [{ ObjectAceFlagsValue: 3 }, { AccessMaskValue: 272 }, { ObjectAceTypeGuid: 'friendly name' }]) {
    assert.equal(removalParameters({ ...object, ...changed }), null);
  }
});

test('unsupported, inherited and incomplete ACEs never offer row removal', () => {
  for (const changed of [{ ACEFlagsValue: 16 }, { ACEFlagsValue: 1 }, { ACEFlagsValue: 7 }, { AccessMaskValue: 0xf01ff | 0x100000 }, { RawSecurityIdentifier: undefined }, { ACEType: 'ACCESS_ALLOWED_CALLBACK_ACE' }, { ACEFlagsValue: undefined }]) {
    assert.equal(removalParameters({ ...ace, ...changed }), null);
  }
});
