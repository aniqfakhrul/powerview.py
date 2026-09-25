import test from 'node:test';
import assert from 'node:assert/strict';
import { createAPI } from '../static/js/core/api.js';
import { createDirectory, objectType } from '../static/js/core/directory.js';
import { splitDN, parentDN, dnLabel, namingContext } from '../static/js/core/dn.js';
import { createRequestLane } from '../static/js/core/request-lane.js';
import { accountDisabled, toTime } from '../static/js/core/ldap-values.js';
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
    assert.deepEqual(bodies[1], { identity: 'People', basedn: 'DC=test', protected: false });
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
  assert.equal(new Date(toTime('24/09/2026 12:18:10')).getDate(), 24);
  assert.equal(new Date(toTime('05/09/2026 00:00:00')).getMonth(), 8);
  assert.ok(toTime('24/09/2026 12:18:10') > toTime('05/09/2026 00:00:00'));
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
