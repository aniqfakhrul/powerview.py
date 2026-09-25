import { values } from './directory.js';

const LINK = /\[LDAP:\/\/cn=(\{[0-9a-f-]+\})[^;\]]*;(\d+)\]/gi;

export function parseGpLink(value) {
  return [...values(value).join('').matchAll(LINK)].map(([, guid, flags]) => ({
    guid,
    disabled: (Number(flags) & 1) !== 0,
    enforced: (Number(flags) & 2) !== 0,
  }));
}

export function linkState(link) {
  return [link.enforced && 'enforced', link.disabled && 'disabled'].filter(Boolean);
}
