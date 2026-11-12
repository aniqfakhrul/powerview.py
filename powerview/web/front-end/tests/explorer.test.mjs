import test from 'node:test';
import assert from 'node:assert/strict';
import { createAPI } from '../static/js/core/api.js';
import { accountKind, createDirectory, objectType, TYPE_ICONS } from '../static/js/core/directory.js';
import { splitDN, parentDN, dnLabel, namingContext } from '../static/js/core/dn.js';
import { createRequestLane } from '../static/js/core/request-lane.js';
import { accountDisabled, readableTime, toTime } from '../static/js/core/ldap-values.js';
import { validateFilter } from '../static/js/components/grid/search-menu.js';

test('DN parsing preserves escaped separators and decodes UTF-8 hex escapes', () => {
  const dn = String.raw`CN=Doe\, Jane,OU=People,DC=example,DC=test`;
  assert.equal(splitDN(dn).length, 4);
  assert.equal(parentDN(dn), 'OU=People,DC=example,DC=test');
  assert.equal(dnLabel(dn), 'Doe, Jane');
  assert.equal(dnLabel(String.raw`CN=Jos\C3\A9,DC=test`), 'José');
  assert.equal(namingContext('CN=Schema,CN=Configuration,DC=test', ['DC=test', 'CN=Configuration,DC=test']), 'CN=Configuration,DC=test');
});

test('computers are classified before users', () => {
  assert.equal(objectType({ attributes: { objectClass: ['top', 'person', 'user', 'computer'] } }), 'computer');
});

test('AD object classes map to Active Directory-like types and icons', () => {
  const type = (objectClass, extra = {}) => objectType({ attributes: { objectClass, ...extra } });
  const computer = ['top', 'person', 'organizationalPerson', 'user', 'computer'];
  assert.equal(type(computer, { userAccountControl: 4096 }), 'computer');
  assert.equal(type(computer, { userAccountControl: [532480] }), 'controller');
  assert.equal(type(computer, { userAccountControl: '83890176' }), 'controller');
  assert.equal(type(computer, { userAccountControl: ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION'] }), 'controller');
  assert.equal(type(computer, { userAccountControl: ['WORKSTATION_TRUST_ACCOUNT', 'TRUSTED_TO_AUTH_FOR_DELEGATION', 'PARTIAL_SECRETS_ACCOUNT'] }), 'controller');
  assert.equal(type(computer, { userAccountControl: ['WORKSTATION_TRUST_ACCOUNT'] }), 'computer');
  assert.equal(type([...computer, 'msDS-GroupManagedServiceAccount'], { userAccountControl: 4096 }), 'service');
  assert.equal(type([...computer, 'msDS-ManagedServiceAccount']), 'service');
  assert.equal(type(['top', 'person', 'organizationalPerson', 'user', 'inetOrgPerson']), 'user');
  assert.equal(type(['top', 'person', 'organizationalPerson', 'contact']), 'contact');
  assert.equal(type(['top', 'foreignSecurityPrincipal']), 'foreign');
  assert.equal(type(['top', 'leaf', 'connectionPoint', 'printQueue']), 'printer');
  assert.equal(type(['top', 'leaf', 'connectionPoint', 'volume']), 'share');
  assert.equal(type(['top', 'pKICertificateTemplate']), 'certificate');
  assert.equal(type(['top', 'builtinDomain']), 'container');
  assert.equal(type(['top', 'domain', 'domainDNS']), 'domain');
  assert.equal(type(['top', 'dnsNode']), 'dns');
  assert.equal(type(['top', 'organizationalUnit']), 'ou');
  assert.equal(type(['top', 'nTDSService']), 'other');
  assert.equal(TYPE_ICONS.controller, 'server');
  assert.equal(accountKind('controller'), 'computer');
  assert.equal(accountKind('service'), 'service');
});

test('every type icon exists exactly once in the sprite', async () => {
  const { readFile } = await import('node:fs/promises');
  const sprite = await readFile(new URL('../static/images/icons.svg', import.meta.url), 'utf8');
  const ids = [...sprite.matchAll(/<symbol id="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length);
  for (const id of Object.values(TYPE_ICONS)) assert.ok(ids.includes(id), id);
});

test('starting a new read cancels the previous signal', () => {
  const lane = createRequestLane(); const first = lane.next(); const second = lane.next();
  assert.equal(first.aborted, true); assert.equal(second.aborted, false);
});

test('transport preserves prefixes, never retries, and rejects non-true mutation results', async () => {
  const original = globalThis.fetch;
  try {
    for (const body of [false, null, {}, 'true']) {
      let calls = 0;
      globalThis.fetch = async (url, options) => {
        calls += 1; assert.equal(url.pathname, '/pv/api/set/domainobject');
        assert.equal(options.method, 'POST'); assert.equal(options.credentials, 'same-origin');
        return new Response(JSON.stringify(body));
      };
      await assert.rejects(createAPI('http://localhost/pv/api/')('set/domainobject', { body: {}, mutation: true }), /did not confirm/);
      assert.equal(calls, 1);
    }
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'Access denied' }), { status: 400 });
    await assert.rejects(createAPI('http://localhost/api/')('get/domainobject'), /Access denied/);
  } finally { globalThis.fetch = original; }
});

test('failed requests ask the shell to recheck the connection', async () => {
  const original = { fetch: globalThis.fetch, dispatch: globalThis.dispatchEvent };
  const events = [];
  try {
    globalThis.dispatchEvent = (event) => events.push(event.type);
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'socket closed' }), { status: 400 });
    await assert.rejects(createAPI('http://localhost/api/')('get/domainobject'), /socket closed/);
    globalThis.fetch = async () => { throw new TypeError('network'); };
    await assert.rejects(createAPI('http://localhost/api/')('get/domainobject'), /Cannot reach/);
    assert.deepEqual(events, ['powerview:request-failed', 'powerview:request-failed']);
  } finally {
    globalThis.fetch = original.fetch;
    globalThis.dispatchEvent = original.dispatch;
  }
});

test('directory edits use structured values and OU creation supplies required args', async () => {
  const original = globalThis.fetch; const bodies = [];
  try {
    globalThis.fetch = async (_url, options) => { bodies.push(JSON.parse(options.body)); return new Response('true'); };
    const directory = createDirectory('http://localhost/api/');
    await directory.edit('CN=A,DC=test', 'DC=test', '_set', 'description', ['a,b=c', 'line\nbreak']);
    assert.deepEqual(bodies[0]._set, { attribute: 'description', value: ['a,b=c', 'line\nbreak'] });
    await directory.create('ou', 'People', '', 'DC=test');
    assert.deepEqual(bodies[1], { identity: 'People', basedn: 'DC=test' });
    assert.throws(() => directory.edit('CN=A', 'DC=test', '_set', 'description', ['@file']), /file/);
    assert.equal(bodies.length, 2);
  } finally { globalThis.fetch = original; }
});

test('account state reads numeric and flag-name userAccountControl values', () => {
  assert.equal(accountDisabled(514), true);
  assert.equal(accountDisabled('512'), false);
  assert.equal(accountDisabled(['NORMAL_ACCOUNT', 'ACCOUNTDISABLE']), true);
  assert.equal(accountDisabled('NORMAL_ACCOUNT DONT_EXPIRE_PASSWORD'), false);
});

test('directory times parse every backend shape chronologically', () => {
  const expected = Date.UTC(2026, 8, 24, 12, 18, 10);
  assert.equal(toTime('Thu, 24 Sep 2026 12:18:10 GMT'), expected);
  assert.equal(toTime('20260924121810.0Z'), expected);
  assert.equal(toTime('20260924121810'), expected);
  assert.equal(toTime(expected * 10000 + 116444736000000000), expected);
  assert.equal(toTime('24/09/2026 12:18:10'), expected);
  assert.equal(toTime('24/09/2026 12:18:10 (2 days ago)'), expected);
  assert.equal(new Date(toTime('05/09/2026 00:00:00')).getUTCMonth(), 8);
  assert.ok(toTime('24/09/2026 12:18:10') > toTime('05/09/2026 00:00:00'));
  assert.deepEqual(readableTime('24/09/2026 12:18:10 (2 days ago)'), { text: new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(expected), relative: '2 days ago' });
  assert.equal(readableTime('20260924121810.0Z')?.relative, '');
  for (const text of ['24/09/2026 notes', '20260924121810', 'Finance analyst']) assert.equal(readableTime(text), null);
  for (const never of [0, '0', '', null, 'Fri, 31 Dec 9999 23:59:59 GMT', 'Mon, 01 Jan 1601 00:00:00 GMT']) assert.equal(toTime(never), null);
});

test('LDAP filter check requires wrapping and balanced parentheses', () => {
  assert.equal(validateFilter(''), '');
  assert.equal(validateFilter('(mail=*)'), '');
  assert.equal(validateFilter('(&(mail=*)(cn=a\\29b))'), '');
  assert.match(validateFilter('mail=*'), /parentheses/);
  assert.match(validateFilter('((mail=*)'), /opening/);
  assert.match(validateFilter('(mail=*))(cn=a)'), /closing/);
});
