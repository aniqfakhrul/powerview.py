/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const DAY = 86_400_000;
const filetime = (ms) => String((ms + 11_644_473_600_000) * 10_000);
const group = (name) => `CN=${name},CN=Users,${root}`;
const user = (name, attributes = {}) => ({ dn: `CN=${name},CN=Users,${root}`, attributes: { name, sAMAccountName: name.toLowerCase(), userAccountControl: 512, ...attributes } });
let users = [
  user('Alice', { department: 'IT', memberOf: [group('GA'), group('GB')], lastLogonTimestamp: filetime(Date.now() - 2 * DAY) }),
  user('Bob', { userAccountControl: 514, memberOf: [group('GB')], lastLogonTimestamp: filetime(Date.now() - 200 * DAY) }),
  user('Carol', { department: 'HR' }),
  user('Dave', { department: 'IT', memberOf: group('GA'), lastLogonTimestamp: filetime(Date.now() - 45 * DAY) }),
  ...Array.from({ length: 6 }, (_, index) => user(`Svc${index + 1}`, { department: 'Service' })),
];

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(() => localStorage.setItem('powerview.users.columns', JSON.stringify(['account', 'status', 'department', 'attr:memberOf', 'groups', 'lastLogon'])));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
      if (path.endsWith('/schema/attributes')) return route.fulfill({ json: { available: false, class: 'user', attributes: [] } });
      const data = route.request().postDataJSON();
      if (path.endsWith('/get/domainuser')) return route.fulfill({ json: data?.search_scope === 'BASE' ? users.filter((item) => item.dn === data.searchbase) : users });
      if (path.endsWith('/get/domainobject')) return route.fulfill({ json: users.filter((item) => item.dn === data.searchbase).map((item) => ({ ...item, attributes: { ...item.attributes, objectClass: ['top', 'person', 'user'] } })) });
      if (path.endsWith('/get/domainobjectacl') || path.endsWith('/get/domainobjectowner')) return route.fulfill({ json: [] });
      if (path.endsWith('/add/domainuser')) {
        users = [...users, user(data.username)];
        return route.fulfill({ json: true });
      }
      throw new Error(`Unexpected API request: ${path}`);
    });
    const rows = page.locator('#grid-body tr[data-dn]');
    const names = async () => (await rows.locator('.cell-name span').allTextContents()).sort();
    const count = () => page.locator('#grid-count').textContent();
    const menu = page.locator('#column-filter');
    const trigger = (key) => page.locator(`th[data-key="${key}"] .column-filter-trigger`);
    const open = async (key) => { await trigger(key).click(); await menu.waitFor(); };
    const option = (label) => menu.locator('.fields-menu__list label').filter({ has: page.getByText(label, { exact: true }) }).locator('input');
    const close = async () => { await page.keyboard.press('Escape'); await menu.waitFor({ state: 'hidden' }); };

    await page.goto(`${base}/users`);
    await rows.first().waitFor();
    assert.equal(await count(), '10 users');
    const widths = () => page.$$eval('#grid-head th', (cells) => cells.map((cell) => Math.round(cell.getBoundingClientRect().width)));
    const idle = await widths();
    assert.deepEqual(idle.slice(1), [240, 180, 110, 180, 200, 130, 190]);
    for (const key of ['name', 'account', 'status', 'department', 'attr:memberOf', 'groups', 'lastLogon']) {
      await page.locator(`th[data-key="${key}"]`).hover();
      assert.deepEqual(await widths(), idle, `hovering ${key} changed column widths`);
    }
    await page.mouse.move(5, 5);
    assert.equal(await page.getByRole('button', { name: /^Search options/ }).count(), 1);
    assert.equal(await page.locator('#grid-clear-filters').isHidden(), true);

    await open('status');
    await trigger('status').click();
    await menu.waitFor({ state: 'hidden' });
    await open('status');
    await trigger('department').click();
    await page.waitForFunction(() => document.querySelector('#column-filter').getAttribute('aria-label') === 'Filter department');
    assert.equal(await menu.isVisible(), true);
    assert.equal(await trigger('status').getAttribute('aria-expanded'), 'false');
    await close();
    await open('status');
    assert.equal(await menu.locator('input[type="search"]').isHidden(), true);
    assert.deepEqual(await menu.locator('.fields-menu__list .fields-menu__label').allTextContents(), ['Enabled', 'Disabled']);
    assert.deepEqual(await menu.locator('.fields-menu__list .fields-menu__hint').allTextContents(), ['9', '1']);
    await option('Disabled').uncheck();
    assert.equal(await count(), '9 of 10 users');
    assert.equal(await menu.isVisible(), true);
    await close();
    assert.equal(await page.evaluate(() => document.activeElement.matches('th[data-key="status"] .column-filter-trigger')), true);
    assert.match(await trigger('status').getAttribute('class'), /is-active/);
    assert.equal(await trigger('status').getAttribute('aria-label'), 'Filter Status, filter active');
    assert.equal(await page.locator('#grid-clear-filters').isVisible(), true);

    await open('attr:memberOf');
    assert.deepEqual(await menu.locator('.fields-menu__list .fields-menu__label').allTextContents(), [group('GA'), group('GB'), '(Empty)']);
    assert.deepEqual(await menu.locator('.fields-menu__list .fields-menu__hint').allTextContents(), ['2', '1', '7']);
    await menu.locator('.column-filter__all input').uncheck();
    assert.equal(await count(), '0 of 10 users');
    await option(group('GB')).check();
    assert.deepEqual(await names(), ['Alice']);
    await option(group('GA')).check();
    assert.deepEqual(await names(), ['Alice', 'Dave']);
    assert.equal(await menu.locator('.column-filter__all input').evaluate((box) => box.indeterminate), true);
    await close();

    await page.locator('#grid-clear-filters').click();
    assert.equal(await count(), '10 users');
    assert.equal(await page.locator('#grid-clear-filters').isHidden(), true);

    await open('account');
    await menu.locator('input[type="search"]').fill('svc');
    assert.equal(await menu.locator('.fields-menu__list label').count(), 6);
    await menu.locator('.column-filter__all input').uncheck();
    assert.deepEqual(await names(), ['Alice', 'Bob', 'Carol', 'Dave']);
    await close();

    await open('department');
    assert.deepEqual(await menu.locator('.fields-menu__list .fields-menu__label').allTextContents(), ['HR', 'IT', '(Empty)']);
    await option('(Empty)').uncheck();
    assert.deepEqual(await names(), ['Alice', 'Carol', 'Dave']);
    await close();
    await open('status');
    assert.deepEqual(await menu.locator('.fields-menu__list .fields-menu__label').allTextContents(), ['Enabled', 'Disabled']);
    assert.deepEqual(await menu.locator('.fields-menu__list .fields-menu__hint').allTextContents(), ['3', '0']);
    await close();

    await open('lastLogon');
    const condition = menu.getByRole('combobox', { name: 'lastLogonTimestamp condition' });
    await condition.selectOption('last30');
    assert.deepEqual(await names(), ['Alice']);
    await condition.selectOption('empty');
    assert.deepEqual(await names(), ['Carol']);
    await condition.selectOption('between');
    assert.deepEqual(await names(), ['Alice', 'Carol', 'Dave']);
    const day = (offset) => new Date(Date.now() - offset * DAY).toISOString().slice(0, 10);
    await menu.getByLabel('From date').fill(day(60));
    await menu.getByLabel('To date').fill(day(30));
    assert.deepEqual(await names(), ['Dave']);
    await close();

    await open('groups');
    await menu.getByRole('combobox').selectOption('between');
    await menu.getByLabel('Minimum').fill('2');
    assert.deepEqual(await names(), []);
    await page.getByText('No rows match the column filters.').waitFor();
    await menu.getByRole('button', { name: 'Clear filter' }).click();
    assert.deepEqual(await names(), ['Dave']);

    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('#grid-refresh').disabled);
    assert.deepEqual(await names(), ['Dave']);

    await page.locator('#grid-fields').click();
    await page.getByRole('checkbox', { name: /^lastLogonTimestamp/ }).uncheck();
    await page.getByRole('button', { name: 'Done', exact: true }).click();
    await page.locator('th[data-key="lastLogon"]').waitFor({ state: 'detached' });
    assert.deepEqual(await names(), ['Alice', 'Carol', 'Dave']);

    await page.getByRole('button', { name: 'Clear filters' }).first().click();
    await page.locator('th[data-key="department"] .column-sort').click();
    assert.equal(await menu.isHidden(), true);

    await rows.filter({ hasText: 'Carol' }).click();
    await page.locator('#object-panel').waitFor();
    await open('status');
    await page.keyboard.press('Escape');
    await menu.waitFor({ state: 'hidden' });
    assert.equal(await page.locator('#object-panel').isVisible(), true);
    await page.waitForFunction(() => document.activeElement.matches('th[data-key="status"] .column-filter-trigger'));
    await page.locator('#panel-close').click();

    await open('status');
    await option('Enabled').uncheck();
    await close();
    assert.deepEqual(await names(), ['Bob']);
    await page.getByRole('button', { name: 'New user', exact: true }).click();
    await page.locator('#user-name').fill('Erin');
    await page.locator('#user-password').fill('Secret123!');
    await page.locator('#user-form button[type="submit"]').click();
    await page.locator('.toast', { hasText: 'Column filters cleared to show the new user' }).waitFor();
    assert.deepEqual(await names(), ['Erin']);
    assert.equal(await page.locator('#grid-clear-filters').isHidden(), true);
    assert.doesNotMatch(await trigger('status').getAttribute('class'), /is-active/);
    await page.locator('#grid-filter').fill('');
    await page.locator('#grid-filter').dispatchEvent('input');

    for (const colorScheme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme });
      await page.setViewportSize({ width: 390, height: 844 });
      await open('department');
      const box = await menu.boundingBox();
      assert.ok(box.x >= 0 && box.x + box.width <= 390);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      await close();
    }
    assert.deepEqual(errors, []);
    console.log('PASS: hovering headers never changes column widths, fixed Enabled/Disabled order with zero counts, Escape closes only the popover over an open panel, new objects clear hiding filters, same button toggles closed, switching columns, status choices without search, value counts, multivalue any-match, (Empty), Select all none/some, search then Select all, date presets/Empty/between, number range, empty state, Clear filter/Clear filters, Refresh keeps filters, hiding a column drops its filter, Escape focus return, mobile themes.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
