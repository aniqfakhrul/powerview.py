import { attribute, textValue } from '../../core/directory.js';
import { linkState, parseGpLink } from '../../core/gplink.js';

let linksByPolicy = new Map();

export function setLinkTargets(targets) {
  linksByPolicy = new Map();
  for (const target of targets) {
    for (const link of parseGpLink(target.gPLink)) {
      const key = link.guid.toLowerCase();
      linksByPolicy.set(key, [...(linksByPolicy.get(key) ?? []), { ...link, dn: target.dn, name: target.name }]);
    }
  }
}

export const policyGuid = (record) => textValue(attribute(record, 'name'));
export const policyLinks = (record) => linksByPolicy.get(policyGuid(record).toLowerCase()) ?? [];

export function linkLabel(link) {
  const states = linkState(link);
  return states.length ? `${link.name} (${states.join(', ')})` : link.name;
}
