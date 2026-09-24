import { createAPI, APIError } from './api.js';
import { dnLabel } from './dn.js';

export const TREE_PROPERTIES = ['name', 'objectClass'];
export const values = (value) => value == null ? [] : Array.isArray(value) ? value : [value];
export const textValue = (value) => values(value).map((item) => typeof item === 'object' ? JSON.stringify(item) : String(item)).join('; ');
export function attribute(record, name) {
  const key = Object.keys(record.attributes).find((item) => item.toLowerCase() === name.toLowerCase());
  return key ? record.attributes[key] : undefined;
}
export function objectType(record) {
  const classes = values(attribute(record, 'objectClass')).map((value) => String(value).toLowerCase());
  if (classes.includes('computer')) return 'computer';
  if (classes.includes('user')) return 'user';
  if (classes.includes('group')) return 'group';
  if (classes.includes('organizationalunit')) return 'ou';
  if (classes.includes('domaindns')) return 'domain';
  if (classes.some((value) => ['container', 'builtindomain', 'configuration', 'dmd', 'dnszone'].includes(value))) return 'container';
  return 'other';
}
export const TYPE_LABELS = { domain: 'Domain', user: 'User', group: 'Group', computer: 'Computer', ou: 'Organizational unit', container: 'Container', other: 'Object' };
export const recordName = (record) => textValue(attribute(record, 'name')) || dnLabel(record.dn);
export const isContainer = (record) => ['domain', 'ou', 'container'].includes(objectType(record));

function records(data) {
  if (!Array.isArray(data)) throw new APIError('The directory returned an unexpected object list. Check the CLI logs.');
  return data.filter((item) => item && typeof item.dn === 'string' && item.attributes && typeof item.attributes === 'object');
}

export function createDirectory(baseURL) {
  const request = createAPI(baseURL);
  return {
    domain: (signal) => request('get/domaininfo', { signal }),
    server: (signal) => request('server/info', { signal }),
    async children(dn, { signal, fresh = false } = {}) {
      return records(await request('get/domainobject', {
        signal, body: { searchbase: dn, search_scope: 'LEVEL', properties: TREE_PROPERTIES, no_cache: fresh },
      }));
    },
    async record(dn, { signal, fresh = false } = {}) {
      const result = records(await request('get/domainobject', {
        signal, body: { searchbase: dn, search_scope: 'BASE', properties: ['*'], no_cache: fresh },
      }));
      if (!result.length) throw new APIError('This object was not found. Refresh its container; it may have moved or been deleted.');
      return result[0];
    },
    edit(identity, searchbase, operation, name, fieldValues) {
      if (!['_set', 'append', 'clear'].includes(operation)) throw new Error('Unsupported field operation.');
      // The backend interprets a single @value as a server-side file path.
      if (operation !== 'clear' && fieldValues.length === 1 && String(fieldValues[0]).startsWith('@')) {
        throw new Error('A single value starting with @ is interpreted as a file by PowerView and cannot be edited here.');
      }
      return request('set/domainobject', { mutation: true, body: {
        identity, searchbase, [operation]: operation === 'clear' ? name : { attribute: name, value: fieldValues },
      } });
    },
    move: (identity, destination_dn, searchbase) => request('set/domainobjectdn', {
      mutation: true, body: { identity, destination_dn, searchbase },
    }),
    remove: (identity, searchbase) => request('remove/domainobject', { mutation: true, body: { identity, searchbase } }),
    create(type, name, password, basedn) {
      const bodies = {
        user: { username: name, password, basedn },
        group: { groupname: name, basedn },
        ou: { identity: name, basedn, args: { protectedfromaccidentaldeletion: false } },
      };
      if (!bodies[type]) throw new Error('Unsupported object type.');
      return request(`add/domain${type}`, { mutation: true, body: bodies[type] });
    },
  };
}
