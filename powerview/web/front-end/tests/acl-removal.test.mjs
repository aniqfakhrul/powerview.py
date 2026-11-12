import test from 'node:test';
import assert from 'node:assert/strict';
import { removalParameters } from '../static/js/components/object-panel/acl-removal.js';

const identity = { index: 7, ace: 'a'.repeat(64), dacl: 'b'.repeat(64) };

test('row removal passes the exact selection without reconstructing rights', () => {
  const result = removalParameters({ RemovalIdentity: identity });
  assert.deepEqual(result, { ace: identity });
  assert.notEqual(result.ace, identity);
});

test('missing or malformed exact identities never offer removal', () => {
  for (const value of [undefined, {}, { ...identity, index: -1 }, { ...identity, index: '7' }, { ...identity, ace: 'invalid' }]) {
    assert.equal(removalParameters({ RemovalIdentity: value }), null);
  }
});
