/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const zoneDN = (zone) => `DC=${zone},CN=MicrosoftDNS,DC=DomainDnsZones,${root}`;
const record = (node, attributes) => ({ attributes: Object.fromEntries(Object.entries({ distinguishedName: `DC=${node},${zoneDN('example.test')}`, name: node, ...attributes }).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) });
const records = [
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
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
      if (path.endsWith('/get/domaindnszone')) return failZones
        ? route.fulfill({ status: 500, json: { error: 'Zone lookup failed' } })
        : route.fulfill({ json: ['example.test', 'other.test'].map((name) => ({ dn: zoneDN(name), attributes: { name } })) });
      if (path.endsWith('/get/domaindnsrecord')) return failRecords
        ? route.fulfill({ status: 500, json: { error: 'Record lookup failed' } })
        : route.fulfill({ json: data.zonename === 'example.test' ? records : [] });
      if (path.endsWith('/get/domainobject')) return route.fulfill({ json: [{ dn: data.searchbase, attributes: { name: '@', objectClass: ['dnsNode'] } }] });
      throw new Error(`Unexpected API request: ${path}`);
    });
    await page.goto(`${base}/dns`);
    const rows = page.locator('#grid-body tr[data-dn]');
    await rows.first().waitFor();
    assert.equal(await rows.count(), 3);
    assert.equal(await page.locator('#grid-search').isVisible(), false);
    assert.equal(requests.some(({ path }) => path.includes('/schema/')), false);
    assert.deepEqual((await rows.locator('.cell-name span').allTextContents()).sort(), ['@', '@', '_ldap._tcp'].sort());
    assert.match(await rows.filter({ hasText: '_ldap._tcp' }).innerText(), /dc.example.test\./);
    assert.match(await rows.filter({ hasText: '_ldap._tcp' }).innerText(), /389/);
    await page.locator('th[data-key="ttl"] button').click();
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
    console.log('PASS: parsed DNS rows, duplicate node records, apex/SRV names, numeric sorting, filtering, Fields, zone selection, panel closure, failures/retry, fresh reads, no schema lookup, mobile themes.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
