import { dnLabel } from '../../core/dn.js';

export function aclEntries(result) {
  if (!Array.isArray(result)) throw new Error('No ACL result was returned. Check the identity, session, and directory permissions, then retry.');
  return result.flatMap((group, objectIndex) => {
    if (!Array.isArray(group?.attributes)) throw new Error('The ACL endpoint returned an unexpected result.');
    return group.attributes.map((ace, aceIndex) => {
      if (!ace || typeof ace !== 'object' || Array.isArray(ace)) throw new Error('The ACL endpoint returned an invalid ACE.');
      const dn = typeof ace.ObjectDN === 'string' ? ace.ObjectDN : '';
      const effect = String(ace.ACEType ?? '').includes('DENIED') ? 'Deny'
        : String(ace.ACEType ?? '').includes('ALLOWED') ? 'Allow' : 'Unsupported';
      return {
        id: `${objectIndex}:${aceIndex}`, dn, name: dn ? dnLabel(dn) : 'Unknown target',
        record: { dn, attributes: { ...ace, Effect: effect, Rights: ace.ActiveDirectoryRights || ace.AccessMask || '', ACEIndex: aceIndex + 1 } },
      };
    });
  });
}
