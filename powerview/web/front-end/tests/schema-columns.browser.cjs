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
  { name: 'description', kind: 'text', singleValued: true },
  { name: 'extensionAttribute1', kind: 'text', singleValued: true },
  { name: 'extensionAttribute2', kind: 'text', singleValued: true },
  { name: 'name', kind: 'text', singleValued: true },
  { name: 'objectSid', kind: 'sid', singleValued: true },
  { name: 'sAMAccountName', kind: 'text', singleValued: true },
  { name: 'userCertificate', kind: 'binary', singleValued: false },
  ...Array.from({ length: 60 }, (_, index) => ({ name: `extraAttribute${index}`, kind: 'text', singleValued: true })),
];

async function openUsers(browser, { savedKeys, gate }) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 500 } });
  const state = { errors: [], listRequests: [] };
  page.on('pageerror', (error) => state.errors.push(error.message));
  await page.addInitScript((keys) => localStorage.setItem('powerview.users.columns', JSON.stringify(keys)), savedKeys);
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/schema/attributes')) { await gate; return route.fulfill({ json: { available: true, class: 'user', attributes: schema } }); }
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
    if (path.endsWith('/get/domainuser')) { state.listRequests.push(route.request().postDataJSON()); return route.fulfill({ json: users }); }
    return route.fulfill({ json: [] });
  });
  await page.goto(`${base}/users`);
  await page.locator('#grid-body tr[data-dn]').first().waitFor();
  return { page, state };
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  let releaseSchema;
  const gate = new Promise((resolve) => { releaseSchema = resolve; });
  const { page, state } = await openUsers(browser, { savedKeys: ['account', 'attr:accountexpires'], gate });

  const header = page.getByRole('button', { name: 'accountexpires', exact: true });
  await header.focus();
  await page.locator('#grid-scroll').evaluate((node) => { node.scrollTop = 600; });
  releaseSchema();
  await page.getByRole('button', { name: 'accountExpires', exact: true }).waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'accountExpires');
  assert.equal(await page.locator('#grid-scroll').evaluate((node) => node.scrollTop), 600);
  assert.match(await page.locator('#grid-body tr[data-dn]').first().locator('td').nth(3).textContent(), /2025/);

  const fields = page.locator('#fields-menu');
  const find = fields.getByRole('searchbox', { name: 'Find a field' });
  const suggestions = fields.locator('.fields-menu__suggestions .fields-menu__option');
  await page.getByRole('button', { name: /^Fields/ }).click();
  assert.equal(await fields.getByRole('checkbox', { name: /^accountExpires/ }).isChecked(), true);
  await find.fill('extension');
  assert.equal(await suggestions.count(), 2);
  await fields.getByRole('checkbox', { name: 'extensionAttribute1, schema attribute' }).click();
  assert.equal(await find.inputValue(), 'extension');
  assert.equal(await fields.getByRole('checkbox', { name: /^extensionAttribute1, Custom/ }).isChecked(), true);
  assert.equal(await suggestions.count(), 1);
  for (const covered of ['description', 'name']) {
    await find.fill(covered);
    assert.equal(await fields.locator('.fields-menu__suggestions').getByRole('checkbox', { name: `${covered}, schema attribute`, exact: true }).count(), 0);
  }
  await find.fill('objectsid');
  assert.equal(await fields.getByRole('checkbox', { name: 'objectSid, schema attribute' }).isDisabled(), false);
  await find.fill('usercert');
  assert.equal(await fields.getByRole('checkbox', { name: 'userCertificate, binary, not displayable' }).isDisabled(), true);
  await find.fill('extra');
  assert.equal(await suggestions.count(), 50);
  assert.match(await fields.locator('.fields-menu__more').textContent(), /^10 more/);

  await fields.getByText('Add by exact name').click();
  const add = fields.getByRole('textbox', { name: 'Add attribute column' });
  const addButton = fields.locator('.fields-menu__add button[type="submit"]');
  await add.fill('msDS-ResultantPSO');
  await addButton.click();
  assert.match(await fields.locator('.fields-menu__note').textContent(), /isn't listed for user.*Constructed attributes/);
  assert.equal(await addButton.textContent(), 'Add anyway');
  await addButton.click();
  assert.equal(await fields.getByRole('checkbox', { name: /^msDS-ResultantPSO, Custom/ }).isChecked(), true);
  await fields.getByRole('textbox', { name: 'Add attribute column' }).fill('usercertificate');
  await fields.locator('.fields-menu__add button[type="submit"]').click();
  assert.match(await fields.locator('.fields-menu__note').textContent(), /raw bytes/);
  await fields.getByRole('textbox', { name: 'Add attribute column' }).fill('EXTENSIONATTRIBUTE2');
  assert.equal(await fields.locator('.fields-menu__add button[type="submit"]').textContent(), 'Add');
  await fields.locator('.fields-menu__add button[type="submit"]').click();
  assert.equal(await fields.getByRole('checkbox', { name: /^extensionAttribute2, Custom/ }).isChecked(), true);

  const refetch = page.waitForResponse((response) => response.url().endsWith('/get/domainuser'));
  await page.keyboard.press('Escape');
  await refetch;
  assert.deepEqual(JSON.parse(await page.evaluate(() => localStorage.getItem('powerview.users.columns'))),
    ['account', 'attr:accountexpires', 'attr:extensionAttribute1', 'attr:msDS-ResultantPSO', 'attr:extensionAttribute2']);
  for (const name of ['extensionAttribute1', 'extensionAttribute2', 'msDS-ResultantPSO']) assert.equal(state.listRequests.at(-1).properties.includes(name), true);
  assert.deepEqual(state.errors, []);
  await page.close();

  let releaseLate;
  const lateGate = new Promise((resolve) => { releaseLate = resolve; });
  const late = await openUsers(browser, { savedKeys: ['account'], gate: lateGate });
  await late.page.getByRole('button', { name: /^Fields/ }).click();
  await late.page.locator('#fields-menu').getByRole('searchbox', { name: 'Find a field' }).fill('extension');
  assert.equal(await late.page.locator('#fields-menu .fields-menu__suggestions .fields-menu__option').count(), 0);
  releaseLate();
  await late.page.waitForFunction(() => document.querySelectorAll('#fields-menu .fields-menu__suggestions .fields-menu__option').length === 2);
  assert.equal(await late.page.locator('#fields-menu').getByRole('searchbox', { name: 'Find a field' }).inputValue(), 'extension');
  assert.deepEqual(late.state.errors, []);

  console.log('PASS: stable saved keys, late schema keeps focus/scroll and refreshes open suggestions, FILETIME dates, suggestions (match, keep search, curated and name exclusions, readable SID enabled, raw binary disabled, 50 cap), manual fallback with constructed and binary overrides, canonical casing.');
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
