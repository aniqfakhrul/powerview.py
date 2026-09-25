/** Run against a local shell preview. Every API call is intercepted with test fixtures. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const users = Array.from({ length: 120 }, (_, index) => ({ dn: `CN=User ${index},CN=Users,${rootDN}`, attributes: {
  name: `User ${index}`, sAMAccountName: `user${index}`, userAccountControl: 512, accountExpires: String(134031178900000000 + index),
} }));
const schema = [
  { name: 'accountExpires', kind: 'time', singleValued: true },
  { name: 'sAMAccountName', kind: 'text', singleValued: true },
];

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 500 } });
  const errors = [];
  let releaseSchema;
  const schemaGate = new Promise((resolve) => { releaseSchema = resolve; });
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => localStorage.setItem('powerview.users.columns', JSON.stringify(['account', 'attr:accountexpires'])));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/schema/attributes')) { await schemaGate; return route.fulfill({ json: { available: true, class: 'user', attributes: schema } }); }
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
    if (path.endsWith('/get/domainuser')) return route.fulfill({ json: users });
    return route.fulfill({ json: [] });
  });

  await page.goto(`${base}/users`);
  await page.locator('#grid-body tr[data-dn]').first().waitFor();
  const header = page.getByRole('button', { name: 'accountexpires', exact: true });
  await header.focus();
  await page.locator('#grid-scroll').evaluate((node) => { node.scrollTop = 600; });
  releaseSchema();
  await page.getByRole('button', { name: 'accountExpires', exact: true }).waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'accountExpires');
  assert.equal(await page.locator('#grid-scroll').evaluate((node) => node.scrollTop), 600);
  assert.match(await page.locator('#grid-body tr[data-dn]').first().locator('td').nth(3).textContent(), /2025/);

  await page.getByRole('button', { name: /^Fields/ }).click();
  assert.equal(await page.locator('#fields-menu').getByRole('checkbox', { name: /^accountExpires/ }).isChecked(), true);
  await page.keyboard.press('Escape');
  assert.deepEqual(JSON.parse(await page.evaluate(() => localStorage.getItem('powerview.users.columns'))), ['account', 'attr:accountexpires']);
  assert.deepEqual(errors, []);
  console.log('PASS: saved custom keys stay stable after schema casing, late schema keeps header focus and scroll, schema kind formats FILETIME as date.');
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
