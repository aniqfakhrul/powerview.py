/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const zoneDN = (zone) => `DC=${zone},CN=MicrosoftDNS,DC=DomainDnsZones,${root}`;
const record = (node, attributes) => ({ attributes: Object.fromEntries(Object.entries({ distinguishedName: `DC=${node},${zoneDN('example.test')}`, name: node, ...attributes }).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) });
let records = [
  record('@', { RecordType: 'A', Address: '192.0.2.1', TTL: 600, TimeStamp: 0 }),
  record('@', { RecordType: 'NS', Address: 'ns.example.test.', TTL: 3600 }),
  record('_ldap._tcp', { RecordType: 'SRV', Name: 'dc.example.test.', Port: 389, TTL: 60, Priority: 0, Weight: 100 }),
];
(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const requests = []; const errors = []; let failZones = false; let failRecords = false;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      const data = route.request().postDataJSON();
      requests.push({ path, data });
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol: 'LDAPS' } });
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root, `DC=DomainDnsZones,${root}`] } } });
      if (path.endsWith('/get/domaindnszone')) return failZones
        ? route.fulfill({ status: 500, json: { error: 'Zone lookup failed' } })
        : route.fulfill({ json: ['_msdcs.example.test', 'example.test', 'other.test'].map((name) => ({ dn: zoneDN(name), attributes: { name } })) });
      if (path.endsWith('/get/domaindnsrecord')) return failRecords
        ? route.fulfill({ status: 500, json: { error: 'Record lookup failed' } })
        : route.fulfill({ json: data.zonename === 'example.test' ? records : [] });
      if (path.endsWith('/add/domaindnsrecord')) {
        if (records.some((item) => item.attributes.name === data.recordname)) return route.fulfill({ status: 400, json: { error: 'LDAPEntryAlreadyExistsResult - 68 - entryAlreadyExists' } });
        records = [...records, ...['10.0.0.25', '10.0.0.26'].map((Address) => record(data.recordname, { RecordType: 'A', Address, TTL: 600 }))];
        return route.fulfill({ json: true });
      }
      if (path.endsWith('/set/domaindnsrecord')) {
        records = records.map((item) => (item.attributes.distinguishedName === data.recordname && item.attributes.Address === data.oldaddress
          ? record(item.attributes.name, { ...item.attributes, Address: data.recordaddress })
          : item));
        return route.fulfill({ json: true });
      }
      if (path.endsWith('/remove/domainobject')) {
        records = records.filter((item) => item.attributes.distinguishedName !== data.identity);
        return route.fulfill({ json: true });
      }
      if (path.endsWith('/get/domainobject')) return route.fulfill({ json: [{ dn: data.searchbase, attributes: { name: '@', objectClass: ['dnsNode'] } }] });
      throw new Error(`Unexpected API request: ${path}`);
    });
    await page.goto(`${base}/dns`);
    const rows = page.locator('#grid-body tr[data-dn]');
    await rows.first().waitFor();
    assert.equal(await rows.count(), 3);
    assert.equal(await page.locator('#dns-zone').inputValue(), 'example.test');
    assert.equal(new URL(page.url()).searchParams.get('zone'), 'example.test');
    assert.equal(await page.locator('#grid-search').isVisible(), false);
    assert.equal(requests.some(({ path }) => path.includes('/schema/')), false);
    assert.deepEqual((await rows.locator('.cell-name span').allTextContents()).sort(), ['@', '@', '_ldap._tcp'].sort());
    assert.match(await rows.filter({ hasText: '_ldap._tcp' }).innerText(), /dc.example.test\./);
    assert.match(await rows.filter({ hasText: '_ldap._tcp' }).innerText(), /389/);
    assert.equal(await rows.filter({ hasText: '_ldap._tcp' }).locator('.state--neutral').textContent(), 'SRV');
    await page.locator('th[data-key="ttl"] .column-sort').click();
    assert.deepEqual(await rows.locator('.cell-name span').allTextContents(), ['_ldap._tcp', '@', '@']);
    await page.locator('#grid-filter').fill('192.0.2.1');
    assert.equal(await rows.count(), 1);
    await page.locator('#grid-filter').fill('');
    await rows.first().click();
    await page.getByRole('tab', { name: 'Attributes', exact: true }).waitFor();
    assert.equal(await page.locator('#object-panel').isVisible(), true);
    await page.locator('#dns-zone').selectOption('other.test');
    await page.getByText('No records found', { exact: true }).waitFor();
    assert.equal(await page.locator('#object-panel').isVisible(), false);
    assert.equal(new URL(page.url()).searchParams.has('dn'), false);
    await page.locator('#dns-zone').selectOption('example.test');
    await rows.first().waitFor();
    const mutations = () => requests.filter(({ path }) => /\/(add\/domaindnsrecord|remove\/domainobject)$/.test(path));
    await page.getByRole('button', { name: 'New record', exact: true }).click();
    const dialog = page.locator('#dns-dialog');
    assert.equal(await dialog.locator('#dns-dialog-zone').textContent(), 'example.test');
    await dialog.getByRole('textbox', { name: 'Name' }).fill('web01');
    await dialog.getByRole('textbox', { name: 'IPv4 address' }).fill('10.0.0.256');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await dialog.getByText(/Enter an IPv4 address/).waitFor();
    await dialog.getByRole('textbox', { name: 'Name' }).fill('@');
    await dialog.getByRole('textbox', { name: 'IPv4 address' }).fill('10.0.0.25');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await dialog.getByText(/Enter a host name/).waitFor();
    await dialog.getByRole('textbox', { name: 'Name' }).fill('Example.Test.');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await dialog.getByText('Enter a host name such as web01; it is created in example.test.').waitFor();
    assert.equal(mutations().length, 0);
    await dialog.getByRole('textbox', { name: 'Name' }).fill('web01.EXAMPLE.test.');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await page.locator('.toast--success', { hasText: 'Created web01.example.test' }).waitFor();
    assert.deepEqual(mutations()[0].data, { recordname: 'web01', recordaddress: '10.0.0.25', zonename: 'example.test', no_cache: true });
    await page.waitForFunction(() => document.querySelectorAll('#grid-body tr[data-dn]').length === 5);
    await page.getByRole('button', { name: 'New record', exact: true }).click();
    await dialog.getByRole('textbox', { name: 'Name' }).fill('web01');
    await dialog.getByRole('textbox', { name: 'IPv4 address' }).fill('10.0.0.27');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await dialog.getByText('web01.example.test already exists. Delete it first or choose another name.').waitFor();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await rows.filter({ hasText: '192.0.2.1' }).click();
    await page.getByRole('tab', { name: 'Attributes', exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name: 'Delete object' }).count(), 0);
    await rows.filter({ hasText: '_ldap._tcp' }).click();
    await page.getByRole('button', { name: 'Delete object' }).waitFor();
    assert.equal(await page.getByRole('button', { name: 'Edit address' }).count(), 0);
    await rows.filter({ hasText: '10.0.0.26' }).click();
    await page.getByRole('button', { name: 'Edit address' }).click();
    const edit = page.locator('#dns-edit-dialog');
    assert.equal(await edit.locator('#dns-edit-context').textContent(), 'web01.example.test');
    assert.deepEqual(await edit.locator('#dns-edit-current option').allTextContents(), ['10.0.0.25', '10.0.0.26']);
    await edit.locator('#dns-edit-current').selectOption('10.0.0.26');
    await edit.getByRole('textbox', { name: 'New address' }).fill('10.0.0.300');
    await edit.getByRole('button', { name: 'Save' }).click();
    await edit.getByText(/Enter an IPv4 address/).waitFor();
    await edit.getByRole('textbox', { name: 'New address' }).fill('10.0.0.26');
    await edit.getByRole('button', { name: 'Save' }).click();
    await edit.getByText('The new address is the same as the current one.').waitFor();
    assert.equal(requests.some(({ path }) => path.endsWith('/set/domaindnsrecord')), false);
    await edit.getByRole('textbox', { name: 'New address' }).fill('10.0.0.30');
    await edit.getByRole('button', { name: 'Save' }).click();
    await page.locator('.toast--success', { hasText: 'Updated web01.example.test: 10.0.0.26 → 10.0.0.30' }).waitFor();
    assert.deepEqual(requests.filter(({ path }) => path.endsWith('/set/domaindnsrecord')).at(-1).data,
      { recordname: `DC=web01,${zoneDN('example.test')}`, recordaddress: '10.0.0.30', oldaddress: '10.0.0.26', zonename: 'example.test' });
    await rows.filter({ hasText: '10.0.0.30' }).waitFor();
    assert.equal(await rows.filter({ hasText: '10.0.0.26' }).count(), 0);
    assert.equal(await rows.filter({ hasText: '10.0.0.25' }).count(), 1);
    await rows.filter({ hasText: '10.0.0.30' }).click();
    await page.getByRole('button', { name: 'Delete object' }).click();
    const readsBeforeDelete = requests.length;
    const confirm = page.getByRole('dialog', { name: 'Delete web01.example.test?' });
    await confirm.getByText('This removes all 2 records at this name: A 10.0.0.25, A 10.0.0.30.').waitFor();
    await confirm.getByRole('button', { name: 'Delete', exact: true }).click();
    await page.locator('.toast--success', { hasText: 'Deleted' }).waitFor();
    assert.deepEqual(mutations().at(-1).data, { identity: `DC=web01,${zoneDN('example.test')}`, searchbase: `DC=DomainDnsZones,${root}` });
    await page.waitForFunction(() => document.querySelectorAll('#grid-body tr[data-dn]').length === 3);
    const freshAfterDelete = () => requests.slice(readsBeforeDelete).some(({ path, data }) => path.endsWith('/get/domaindnsrecord') && data.no_cache === true);
    for (let attempt = 0; attempt < 50 && !freshAfterDelete(); attempt += 1) await page.waitForTimeout(100);
    assert.ok(freshAfterDelete());
    assert.equal(await rows.count(), 3);
    await page.locator('#grid-fields').click();
    await page.getByRole('checkbox', { name: /Priority/ }).check();
    await page.getByRole('button', { name: 'Done', exact: true }).click();
    await page.locator('th[data-key="priority"]').waitFor();
    await rows.first().waitFor();
    failRecords = true;
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.getByText('Record lookup failed', { exact: true }).waitFor();
    failRecords = false;
    await page.getByRole('button', { name: 'Retry', exact: true }).click();
    await rows.first().waitFor();
    assert.equal(requests.filter(({ path }) => path.endsWith('/get/domaindnsrecord')).at(-1).data.no_cache, true);
    failZones = true;
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.getByText('Zone lookup failed', { exact: true }).waitFor();
    failZones = false;
    await page.getByRole('button', { name: 'Retry', exact: true }).click();
    await rows.first().waitFor();
    for (const colorScheme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme });
      await page.setViewportSize({ width: 390, height: 844 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      await page.screenshot({ path: `/tmp/dns-${colorScheme}.png` });
    }
    assert.deepEqual(errors, []);
    console.log('PASS: Edit address changes only the chosen A record and is hidden without A records, defaults to the domain zone, parsed DNS rows, New record validation and fresh reload, apex protected, node delete lists every record, duplicate node records, apex/SRV names, numeric sorting, filtering, Fields, zone selection, panel closure, failures/retry, fresh reads, no schema lookup, mobile themes.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
