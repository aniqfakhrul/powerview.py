import { createAPI, APIError } from './api.js';
import { dnLabel } from './dn.js';

export const TREE_PROPERTIES = ['name', 'objectClass'];
export const values = (value) => value == null ? [] : Array.isArray(value) ? value : [value];
export const textValue = (value) => values(value).map((item) => typeof item === 'object' ? JSON.stringify(item) : String(item)).join('; ');
export function attribute(record, name) {
  if (Object.hasOwn(record.attributes, name)) return record.attributes[name];
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
const PLAIN_NAME = /^[^,=+<>;"\\\x00-\x1f]+$/;
export function assertPlainName(name) {
  if (!PLAIN_NAME.test(name) || name.trim() !== name) throw new Error('Use a plain name without commas, equals signs, or leading and trailing spaces.');
}
export const TYPE_LABELS = { domain: 'Domain', user: 'User', group: 'Group', computer: 'Computer', ou: 'Organizational unit', container: 'Container', other: 'Object' };
export const recordName = (record) => textValue(attribute(record, 'name')) || dnLabel(record.dn);
export const isContainer = (record) => ['domain', 'ou', 'container'].includes(objectType(record));

export function entryFromRecord(record) {
  return { dn: record.dn, name: recordName(record), record };
}

function records(data) {
  if (!Array.isArray(data)) throw new APIError('The directory returned an unexpected object list. Check the CLI logs.');
  return data.filter((item) => item && typeof item.dn === 'string' && item.attributes && typeof item.attributes === 'object');
}

function withDN(data, noun) {
  if (data == null) return [];
  if (!Array.isArray(data)) throw new APIError(`The directory returned an unexpected ${noun}. Check the CLI logs.`);
  return records(data.map((item) => ({ ...item, dn: item?.dn ?? textValue(item?.attributes?.distinguishedName) }))).filter((record) => record.dn);
}

export function createDirectory(baseURL) {
  const request = createAPI(baseURL);
  return {
    domain: (signal) => request('get/domaininfo', { signal }),
    server: (signal) => request('server/info', { signal }),
    connection: (signal) => request('connectioninfo', { signal }),
    createComputer: (computer_name, computer_pass, basedn) => request('add/domaincomputer', {
      mutation: true, body: { computer_name, computer_pass, basedn },
    }),
    async schemaAttributes(className, { signal } = {}) {
      const data = await request(`schema/attributes?class=${encodeURIComponent(className)}`, { signal });
      return data?.available && Array.isArray(data.attributes) ? data.attributes : null;
    },
    async security(dn, { signal, fresh = false } = {}) {
      const body = { identity: dn, searchbase: dn, search_scope: 'BASE', no_cache: fresh };
      const [owners, acls] = await Promise.all([
        request('get/domainobjectowner', { signal, body }),
        request('get/domainobjectacl', { signal, body: { ...body, resolveguids: true } }),
      ]);
      if (!Array.isArray(acls) || !Array.isArray(owners)) {
        throw new APIError('PowerView could not read this object\'s security descriptor. The account may lack permission to read it; check the CLI logs.');
      }
      const owner = owners[0]?.attributes?.Owner ?? '';
      const aces = acls.flatMap((entry) => (Array.isArray(entry?.attributes) ? entry.attributes : []));
      return { owner: textValue(owner), aces };
    },
    async list(endpoint, { signal, fresh = false, properties = ['name'], search = {}, options = {} } = {}) {
      const body = { ...options, properties, raw: true, no_vuln_check: true, no_cache: fresh };
      if (search.base) body.searchbase = search.base;
      if (search.scope) body.search_scope = search.scope;
      const args = Object.fromEntries((search.options ?? []).map((option) => [option, true]));
      if (search.filter) args.ldapfilter = search.filter;
      for (const [key, value] of Object.entries(search)) {
        if (!['base', 'scope', 'filter', 'options'].includes(key) && value) args[key] = value;
      }
      if (Object.keys(args).length) body.args = args;
      const data = await request(endpoint, { signal, body });
      return records(data).map(entryFromRecord);
    },
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
    groupMember: (action, group, member) => request(`${action}/domaingroupmember`, { mutation: true, body: { identity: group, members: member } }),
    async dnsZones({ signal, fresh = false } = {}) {
      return records(await request('get/domaindnszone', { signal, body: { no_cache: fresh } }));
    },
    dnsAddRecord: ({ zone, name, address }) => request('add/domaindnsrecord', {
      mutation: true, body: { recordname: name, recordaddress: address, zonename: zone, no_cache: true },
    }),
    async certificateTemplates({ signal, fresh = false } = {}) {
      const data = await request('get/domaincatemplate', { signal, body: { resolve_sids: true, no_cache: fresh } });
      return withDN(data, 'certificate template list').map(entryFromRecord);
    },
    async certificateAuthorities({ signal, fresh = false, checkWeb = false } = {}) {
      const data = await request('get/domainca', { signal, body: { no_cache: fresh, ...(checkWeb ? { check_all: true } : {}) } });
      return withDN(data, 'certificate authority list').map(entryFromRecord);
    },
    dnsSetRecord: ({ zone, dn, oldAddress, address }) => request('set/domaindnsrecord', {
      mutation: true, body: { recordname: dn, recordaddress: address, oldaddress: oldAddress, zonename: zone },
    }),
    protectFromDeletion: (dn) => request('add/domainobjectacl', {
      mutation: true, body: { targetidentity: dn, principalidentity: 'Everyone', rights: 'immutable', ace_type: 'denied' },
    }),
    async gpoNames({ signal, fresh = false } = {}) {
      const data = await request('get/domaingpo', { signal, body: { properties: ['name', 'displayName'], no_cache: fresh } });
      return new Map(records(data).map((record) => [textValue(attribute(record, 'name')).toLowerCase(), textValue(attribute(record, 'displayName'))]));
    },
    async dnsRecords(zone, { signal, fresh = false } = {}) {
      const data = await request('get/domaindnsrecord', { signal, body: { zonename: zone, no_cache: fresh } });
      return withDN(data, 'DNS record list').map((record) => ({ dn: record.dn, name: dnLabel(record.dn), record }));
    },
    async findObjects(text, { groupsOnly = false, signal } = {}) {
      const escaped = text.replace(/[\\*()\0]/g, (character) => `\\${character.charCodeAt(0).toString(16).padStart(2, '0')}`);
      const match = `(|(name=${escaped}*)(sAMAccountName=${escaped}*))`;
      const data = await request('get/domainobject', { signal, body: {
        properties: ['name', 'objectClass', 'sAMAccountName'],
        ldap_filter: groupsOnly ? `(&(objectCategory=group)${match})` : `(&(|(objectCategory=person)(objectCategory=group)(objectCategory=computer))${match})`,
        raw: true, no_vuln_check: true,
      } });
      return records(data);
    },
    account: (action, identity, searchbase) => request(`account/${action}`, { mutation: true, body: { identity, searchbase } }),
    create(type, name, password, basedn) {
      const bodies = {
        user: { username: name, password, basedn },
        group: { groupname: name, basedn },
        ou: { identity: name, basedn },
      };
      if (!bodies[type]) throw new Error('Unsupported object type.');
      return request(`add/domain${type}`, { mutation: true, body: bodies[type] });
    },
  };
}
