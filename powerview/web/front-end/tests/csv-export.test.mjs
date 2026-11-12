import test from 'node:test';
import assert from 'node:assert/strict';
import { csvCell, csvFilename, toCsv } from '../static/js/components/grid/csv-export.js';
import { dnChipColumn } from '../static/js/components/grid/chips.js';

test('cells are always quoted and embedded quotes are doubled', () => {
  assert.equal(csvCell('Alice'), '"Alice"');
  assert.equal(csvCell('CN=Last\\, First,DC=example'), '"CN=Last\\, First,DC=example"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('line\nbreak'), '"line\nbreak"');
  assert.equal(csvCell(null), '""');
  assert.equal(csvCell(undefined), '""');
});

test('formula prefixes are escaped, plain numbers are not', () => {
  for (const value of ['=HYPERLINK("x")', '+cmd', '-2+3', '@SUM(A1)', '\tvalue', '\rvalue', '\n=1+1', '＝1+1', '＋1+1', '－1+1', '＠SUM(A1)']) {
    assert.ok(csvCell(value).startsWith(`"'`), value);
  }
  assert.equal(csvCell('-2147483646'), '"-2147483646"');
  assert.equal(csvCell('-1.5'), '"-1.5"');
  assert.equal(csvCell(42), '"42"');
});

test('DN chip exports preserve full DNs and mark incomplete LDAP ranges', () => {
  const column = dnChipColumn('members', 'member', 'Members');
  const members = ['CN=Alpha,DC=example', 'CN=Bravo,DC=example'];
  assert.equal(column.csv({ attributes: { member: members } }), members.join('; '));
  assert.equal(column.csv({ attributes: { 'member;range=0-*': members } }), members.join('; '));
  assert.equal(column.csv({ attributes: { 'member;range=0-1': members } }), `${members.join('; ')} [Partial: 2 values returned; more exist]`);
  assert.equal(column.csv({ attributes: {} }), '');
});

test('toCsv writes a header row and one CRLF-separated line per entry', () => {
  const columns = [{ label: 'name', value: (entry) => entry.name }, { label: 'description', value: (entry) => entry.description }];
  const csv = toCsv(columns, [{ name: 'alice', description: '=bad' }, { name: 'bob', description: '' }]);
  assert.equal(csv, '"name","description"\r\n"alice","\'=bad"\r\n"bob",""');
});


test('computer IP exports retain resolved addresses for built-in and custom selections', async () => {
  const { computerColumns } = await import('../static/js/pages/computers/columns.js');
  for (const key of ['ipAddress', 'attr:IPAddress', 'attr:ipaddress']) {
    const columns = computerColumns.columns([key]);
    assert.deepEqual(computerColumns.requestOptions(columns), { include_ip: true });
    assert.ok(!computerColumns.properties(columns).some((name) => name.toLowerCase() === 'ipaddress'));
    const fields = columns.map((column) => ({ label: column.label, value: (entry) => (column.csv ?? column.text)(entry.record, entry) }));
    const csv = toCsv(fields, [{ name: 'PC01', record: { attributes: { IPAddress: ['192.0.2.1', '192.0.2.2'] } } }]);
    assert.equal(csv, '"name","IPAddress"\r\n"PC01","192.0.2.1, 192.0.2.2"');
  }
});


test('CSV filenames identify the connected domain and export view', () => {
  const date = new Date('2026-10-13T20:39:23.000Z');
  for (const view of ['users', 'computers', 'groups', 'dns', 'ca-templates', 'ca-authorities', 'ou', 'gpo', 'pathfinder']) {
    assert.equal(csvFilename(view, 'WONKA.LAB', date), `powerview-wonka.lab-${view}-2026-10-13T20-39-23-000Z.csv`);
  }
  assert.equal(csvFilename('users', '../wonka/lab\\test:', date), 'powerview-wonka-lab-test-users-2026-10-13T20-39-23-000Z.csv');
  for (const domain of [undefined, null, '', '  ', {}, '../']) {
    assert.equal(csvFilename('users', domain, date), 'powerview-unknown-domain-users-2026-10-13T20-39-23-000Z.csv');
  }
});
