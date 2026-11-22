const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const user = (name, attributes = {}) => ({ dn: `CN=${name},CN=Users,${rootDN}`, attributes: { name, sAMAccountName: name.toLowerCase().replace(/\W/g, '.'), userAccountControl: 512, ...attributes } });
const users = [
  user('Alice Admin', { description: '=HYPERLINK("http://example.invalid")', mail: 'alice@example.test' }),
  user('Last, "Quoted"', { description: 'Contractor' }),
  user('Bob Builder', { description: 'Staff', userAccountControl: 514 }),
];
const groups = [{ dn: `CN=Admins,CN=Users,${rootDN}`, attributes: { name: 'Admins', sAMAccountName: 'Admins', groupType: -2147483646, member: [`CN=Alpha,OU=Staff,${rootDN}`, `CN=Bravo,OU=Staff,${rootDN}`] } }];
const aces = [{ attributes: [{ ObjectDN: `CN=svc.backup,${rootDN}`, ACEType: 'ACCESS_ALLOWED_ACE', ACEFlags: [], SecurityIdentifier: 'EXAMPLE\\alex', ActiveDirectoryRights: ['ReadControl', 'WriteDACL'] }] }];

async function download(page) {
  const pending = page.waitForEvent('download');
  await page.locator('#grid-more').click();
  await page.getByRole('menuitem', { name: 'Export CSV' }).click();
  const file = await pending;
  return { name: file.suggestedFilename(), text: await fs.readFile(await file.path(), 'utf8') };
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    await context.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', domain: 'example.test' } });
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [rootDN] } } });
      if (path.endsWith('/get/domainuser')) { await gate; return route.fulfill({ json: users }); }
      if (path.endsWith('/get/domaingroup')) return route.fulfill({ json: groups });
      if (path.endsWith('/get/domainobjectacl')) return route.fulfill({ json: aces });
      return route.fulfill({ json: { status: 'OK', available: false, attributes: [] } });
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(`${base}/users`);
    const button = page.locator('#grid-export');
    const more = page.getByRole('button', { name: 'More actions' });
    assert.equal(await more.getAttribute('aria-haspopup'), 'menu');
    assert.equal(await button.isDisabled(), true);
    release();
    await page.locator('#grid-body tr[data-dn]').nth(2).waitFor();
    assert.equal(await button.isDisabled(), false);
    await more.focus();
    await page.keyboard.press('Enter');
    assert.equal(await more.getAttribute('aria-expanded'), 'true');
    await page.waitForFunction(() => document.activeElement.id === 'grid-export');
    await page.keyboard.press('ArrowDown');
    assert.equal(await page.evaluate(() => document.activeElement.id), 'grid-export');
    await page.keyboard.press('Escape');
    assert.equal(await more.getAttribute('aria-expanded'), 'false');
    await page.waitForFunction(() => document.activeElement.id === 'grid-more');

    await page.locator('#grid-filter').fill('enabled');
    const shown = await page.locator('#grid-body tr[data-dn]').count();
    assert.equal(shown, 2);
    const exported = await download(page);
    assert.match(exported.name, /^powerview-example\.test-users-\d{4}-\d{2}-\d{2}T.*\.csv$/);
    assert.ok(exported.text.startsWith('﻿'));
    const lines = exported.text.slice(1).trimEnd().split('\r\n');
    const labels = await page.locator('#grid-head .column-sort__label').allTextContents();
    assert.equal(lines[0], [...labels, 'distinguishedName'].map((label) => `"${label}"`).join(','));
    assert.equal(lines.length, shown + 1);
    assert.ok(lines.some((line) => line.includes('"\'=HYPERLINK(""http://example.invalid"")"')));
    assert.ok(lines.some((line) => line.startsWith('"Last, ""Quoted"""')));
    assert.ok(lines.some((line) => line.endsWith(`"CN=Alice Admin,CN=Users,${rootDN}"`)));
    assert.ok(!exported.text.includes('Bob Builder'));
    await page.locator('.toast--success', { hasText: 'Exported 2 users to CSV' }).waitFor();
    await page.locator('#grid-filter').fill('no such user');
    assert.equal(await button.isDisabled(), true);

    await page.evaluate(() => localStorage.setItem('powerview.users.columns', JSON.stringify(['attr:distinguishedName'])));
    await page.reload();
    await page.locator('#grid-body tr[data-dn]').nth(2).waitFor();
    const withDN = await download(page);
    assert.equal(withDN.text.split('\r\n')[0].match(/"distinguishedName"/g).length, 1);

    await page.addInitScript(() => localStorage.setItem('powerview.groups.columns', JSON.stringify(['memberNames'])));
    await page.goto(`${base}/groups`);
    await page.locator('#grid-body .cell-chips').first().waitFor();
    const groupsCsv = await download(page);
    assert.match(groupsCsv.name, /^powerview-example\.test-groups-/);
    assert.ok(groupsCsv.text.includes(`"CN=Alpha,OU=Staff,${rootDN}; CN=Bravo,OU=Staff,${rootDN}"`));

    await page.goto(`${base}/pathfinder`);
    assert.equal(await button.isDisabled(), true);
    assert.equal(await page.locator('#more-menu #pathfinder-export').textContent(), 'Export JSON');
    assert.equal(await page.locator('.toolbar #pathfinder-export').count(), 0);
    await page.locator('#pathfinder-target').fill('svc.backup');
    await page.locator('#pathfinder-find').click();
    await page.locator('#grid-body tr[data-key]').first().waitFor();
    const acl = await download(page);
    assert.match(acl.name, /^powerview-example\.test-pathfinder-/);
    assert.match(acl.text.split('\r\n')[0], /"ObjectDN"$/);
    assert.ok(acl.text.includes('"ReadControl; WriteDACL"'));
    assert.deepEqual(errors, []);

    // connectioninfo queues behind the page's own directory load on the server's session lock,
    // so it can arrive late; a late domain still names the file, and a missing one cannot stall it.
    let hold = true;
    let unblock;
    const blocked = new Promise((resolve) => { unblock = resolve; });
    const slow = await browser.newContext({ acceptDownloads: true });
    await slow.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith('/connectioninfo')) {
        await (hold ? blocked : new Promise((resolve) => { setTimeout(resolve, 5500); }));
        return route.fulfill({ json: { status: 'OK', domain: 'example.test' } }).catch(() => {});
      }
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [rootDN] } } });
      if (path.endsWith('/get/domainuser')) return route.fulfill({ json: users });
      return route.fulfill({ json: { status: 'OK', available: false, attributes: [] } });
    });
    const late = await slow.newPage();
    await late.addInitScript(() => { window.requestFailures = 0; addEventListener('powerview:request-failed', () => { window.requestFailures += 1; }); });
    await late.goto(`${base}/users`);
    await late.locator('#grid-body tr[data-dn]').nth(2).waitFor();
    const started = Date.now();
    assert.match((await download(late)).name, /^powerview-unknown-domain-users-/);
    assert.ok(Date.now() - started < 10000);
    hold = false;
    unblock();
    await late.locator('#connection-status[data-state="ok"]').waitFor();
    assert.match((await download(late)).name, /^powerview-example\.test-users-/);
    await late.reload();
    await late.locator('#connection-status[data-state="ok"]').waitFor();
    assert.match((await download(late)).name, /^powerview-example\.test-users-/);
    assert.equal(await late.evaluate(() => window.requestFailures), 0);
    await slow.close();
    console.log('PASS: CSV export on shared grids: disabled while loading and when empty, exports filtered rows with visible columns and DN, BOM and CRLF, quoting, formula neutralisation, no duplicate DN column, DN chip values, More actions menu keyboard behaviour, Pathfinder ObjectDN and JSON menu item, toast and file names, late or missing connection metadata.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
