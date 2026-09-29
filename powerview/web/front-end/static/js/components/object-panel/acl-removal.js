const MEMBER_GUID = 'bf9679c0-0de6-11d0-a285-00aa003049e2';
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function removalParameters(ace) {
  if (!/^S-\d+(?:-\d+)+$/.test(ace.RawSecurityIdentifier ?? '') || ![0, 3].includes(ace.ACEFlagsValue)) return null;
  const allowed = ['ACCESS_ALLOWED_ACE', 'ACCESS_ALLOWED_OBJECT_ACE'].includes(ace.ACEType);
  if (!allowed && !['ACCESS_DENIED_ACE', 'ACCESS_DENIED_OBJECT_ACE'].includes(ace.ACEType)) return null;
  const params = {
    principalidentity: ace.RawSecurityIdentifier,
    ace_type: allowed ? 'allowed' : 'denied',
    inheritance: ace.ACEFlagsValue === 3,
  };
  if (ace.ACEType.endsWith('_OBJECT_ACE')) {
    const guid = ace.ObjectAceTypeGuid?.toLowerCase();
    if (ace.ObjectAceFlagsValue !== 1 || !GUID.test(guid ?? '') || ace.AccessMaskValue !== (guid === MEMBER_GUID ? 0x30 : 0x100)) return null;
    return { ...params, rights: 'fullcontrol', rights_guid: guid };
  }
  if (ace.AccessMaskValue === 0xf01ff) return { ...params, rights: 'fullcontrol' };
  if (!allowed && ace.AccessMaskValue === 0x10040) return { ...params, rights: 'immutable' };
  if (!allowed && ace.AccessMaskValue === 2) return { ...params, rights: 'deletechild' };
  return null;
}
