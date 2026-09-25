/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const guid = (digit) => `{${digit.repeat(8)}-0000-0000-0000-000000000000}`;
const link = (id, flags) => `[LDAP://cn=${id},cn=policies,cn=system,${root};${flags}]`;
const ou = (name, parent, attributes = {}) => ({ dn: `OU=${name},${parent}`, attributes: { name, gPLink: [], gPOptions: [], description: [], ...attributes } });
let ous = [
  ou('Alpha', root, { description: 'First', gPLink: link(guid('1'), 0) + link(guid('2').toLowerCase(), 2) }),
  ou('Bravo', root, { gPLink: link(guid('2'), 1) + link(guid('9'), 0), gPOptions: '1' }),
  ou('Charlie', `OU=Bravo,${root}`),
];
const gpos = [
  { dn: `CN=${guid('1')},${root}`, attributes: { name: guid('1'), displayName: 'Policy One' } },
  { dn: `CN=${guid('2')},${root}`, attributes: { name: guid('2'), displayName: 'Policy Two' } },
];

async function open(browser, { gpoFails = false } = {}) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 800 } });
  const state = { errors: [], lists: [], writes: [] };
  page.on('pageerror', (error) => state.errors.push(error.message));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = route.request().postDataJSON();
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
    if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
    if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
    if (path.endsWith('/schema/attributes')) return route.fulfill({ json: { available: false } });
    if (path.endsWith('/get/domaingpo')) return gpoFails ? route.fulfill({ status: 500, json: { error: 'GPO lookup failed' } }) : route.fulfill({ json: gpos });
    if (path.endsWith('/get/domainou')) {
      state.lists.push(data);
      return route.fulfill({ json: data.search_scope === 'BASE' ? ous.filter((item) => item.dn === data.searchbase) : ous });
    }
    if (path.endsWith('/add/domainou')) {
      state.writes.push(data);
      ous = [...ous, ou(data.identity, data.basedn)];
      return route.fulfill({ json: true });
    }
    if (path.endsWith('/get/domainobject')) return route.fulfill({ json: ous.filter((item) => item.dn === data.searchbase).map((item) => ({ ...item, attributes: { ...item.attributes, objectClass: ['top', 'organizationalUnit'] } })) });
    if (/domainobject(acl|owner)$/.test(path)) return route.fulfill({ json: [] });
    throw new Error(`Unexpected API request: ${path}`);
  });
  await page.goto(`${base}/ou`);
  await page.locator('#grid-body tr[data-dn]').first().waitFor();
  return { page, state };
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const { page, state } = await open(browser);
    const rows = page.locator('#grid-body tr[data-dn]');
    const cell = (name, key) => rows.filter({ hasText: name }).first().locator(`td:nth-child(${2 + ['name', 'parent', 'description', 'gpos', 'inheritance', 'modified'].indexOf(key)})`).innerText();
    assert.equal(await page.locator('#grid-count').textContent(), '3 organizational units');
    assert.deepEqual(await page.locator('#grid-head .column-sort__label').allTextContents(), ['name', 'Parent', 'description', 'Linked GPOs', 'Inheritance', 'whenChanged']);
    assert.deepEqual(state.lists[0].properties.sort(), ['description', 'gPLink', 'gPOptions', 'name', 'whenChanged'].sort());
    await page.waitForFunction(() => document.querySelector('#grid-body').innerText.includes('Policy One'));
    assert.equal(await cell('Alpha', 'gpos'), 'Policy One; Policy Two (enforced)');
    assert.equal(await cell('Bravo', 'gpos'), `Policy Two (disabled); ${guid('9')}`);
    assert.equal(await cell('Bravo', 'inheritance'), 'Blocked');
    assert.equal(await cell('Charlie', 'inheritance'), 'Inherited');
    assert.equal(await cell('Charlie', 'parent'), `OU=Bravo,${root}`);

    const menu = page.locator('#column-filter');
    await page.locator('th[data-key="gpos"] .column-filter-trigger').click();
    assert.deepEqual(await menu.locator('.fields-menu__list .fields-menu__label').allTextContents(), [guid('9'), 'Policy One', 'Policy Two', '(Empty)']);
    await menu.locator('.column-filter__all input').uncheck();
    await menu.getByText('Policy Two', { exact: true }).click();
    assert.deepEqual((await rows.locator('.cell-name span').allTextContents()).sort(), ['Alpha', 'Bravo']);
    await page.keyboard.press('Escape');
    await page.locator('#grid-clear-filters').click();

    await rows.filter({ hasText: 'Alpha' }).click();
    await page.getByRole('tab', { name: 'Policy', exact: true }).click();
    const policy = page.locator('#object-panel .properties:visible');
    assert.match(await policy.innerText(), /Link 2\s+Policy Two\s+\{2{8}[^}]*\}\s+Enforced\s+Link enabled/i);
    await page.getByRole('button', { name: 'Delete object' }).click();
    await page.locator('dialog[open]').getByText(/The OU must be empty/).waitFor();
    await page.locator('dialog[open]').getByRole('button', { name: 'Cancel' }).click();
    await page.locator('#panel-close').click();

    await page.getByRole('button', { name: /^Search options/ }).click();
    await page.locator('#search-menu').getByLabel('Writable by me').check();
    const searched = page.waitForResponse((response) => response.url().endsWith('/get/domainou'));
    await page.locator('#search-menu').getByRole('button', { name: 'Apply' }).click();
    await searched;
    assert.deepEqual(state.lists.at(-1).args, { writable: true });
    await page.getByRole('button', { name: /^Search options/ }).click();
    await page.locator('#search-menu').getByRole('button', { name: 'Clear' }).click();
    const cleared = page.waitForResponse((response) => response.url().endsWith('/get/domainou'));
    await page.locator('#search-menu').getByRole('button', { name: 'Apply' }).click();
    await cleared;

    await page.getByRole('button', { name: 'New OU', exact: true }).click();
    const dialog = page.locator('#ou-dialog');
    assert.equal(await dialog.locator('#ou-container').inputValue(), root);
    await dialog.locator('#ou-name').fill('Bad,Name');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await dialog.locator('#ou-error').waitFor();
    assert.equal(state.writes.length, 0);
    await dialog.locator('#ou-name').fill('Delta');
    await dialog.locator('#ou-protect').check();
    await dialog.getByRole('button', { name: 'Create' }).click();
    await page.locator('.toast--success', { hasText: 'Created Delta' }).waitFor();
    assert.deepEqual(state.writes, [{ identity: 'Delta', basedn: root, protected: true }]);
    await rows.filter({ hasText: 'Delta' }).waitFor();

    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    assert.deepEqual(state.errors, []);
    await page.close();

    const fallback = await open(browser, { gpoFails: true });
    await fallback.page.locator('.toast', { hasText: 'GPO names are unavailable' }).waitFor();
    assert.match(await fallback.page.locator('#grid-body tr', { hasText: 'Alpha' }).innerText(), new RegExp(guid('1').replace(/[{}]/g, '\\$&')));
    assert.deepEqual(fallback.state.errors, []);

    console.log('PASS: OU columns and properties, GPO names with enforced/disabled links and unresolved GUIDs, inheritance, parent path, GPO filter by name, Policy tab, delete guidance, Writable by me search, New OU validation and protection flag, GUID fallback when GPOs fail, mobile overflow.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
