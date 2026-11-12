/** Local preview only; all directory requests are intercepted, including writes. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const requests = []; const errors = []; let fail = false;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: 'DC=example,DC=test' } });
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: ['DC=example,DC=test'] } } });
      if (path.endsWith('/schema/attributes')) return route.fulfill({ json: { available: false, class: 'user', attributes: [] } });
      if (path.endsWith('/get/domainuser')) {
        requests.push(route.request().postDataJSON());
        return fail ? route.fulfill({ status: 400, json: { error: 'Invalid LDAP filter' } }) : route.fulfill({ json: [{ dn: 'CN=A,DC=example,DC=test', attributes: { name: 'A', sAMAccountName: 'a', userAccountControl: 512, memberOf: ['CN=Domain Admins,CN=Users,DC=example,DC=test'] } }] });
      }
      throw new Error(`Unexpected API request: ${path}`);
    });
    await page.goto(`${base}/users`);
    await page.locator('#grid-body tr[data-dn]').waitFor();
    const trigger = page.locator('#grid-search'); const menu = page.locator('#search-menu');
    await trigger.click(); await menu.getByLabel('Password not required', { exact: true }).check();
    await page.keyboard.press('Escape');
    assert.equal(requests.length, 1);
    await trigger.click(); assert.equal(await menu.getByLabel('Password not required', { exact: true }).isChecked(), false);
    await menu.getByLabel('Password not required', { exact: true }).check();
    const adminCount = menu.getByLabel('adminCount set', { exact: true });
    assert.match(await adminCount.getAttribute('aria-description'), /does not prove current administrative access/);
    await adminCount.check();
    await menu.getByLabel('Enabled accounts', { exact: true }).check();
    await menu.getByLabel('Disabled accounts', { exact: true }).check();
    assert.equal(await menu.getByLabel('Enabled accounts', { exact: true }).isChecked(), false);
    await menu.locator('summary').click();
    await menu.getByLabel('Search base', { exact: true }).fill('OU=People,DC=example,DC=test');
    await menu.getByLabel('Scope', { exact: true }).selectOption('LEVEL');
    await menu.getByLabel('LDAP filter', { exact: true }).fill('(mail=*)');
    await menu.getByLabel('Member of', { exact: true }).fill('Domain Admins');
    await menu.getByLabel('Department', { exact: true }).fill('IT');
    await menu.getByLabel('Identity', { exact: true }).fill('a*');
    assert.equal(requests.length, 1);
    await menu.getByRole('button', { name: 'Apply', exact: true }).click();
    await page.locator('#grid-body tr[data-dn]').waitFor();
    const query = requests.at(-1);
    assert.equal(query.searchbase, 'OU=People,DC=example,DC=test'); assert.equal(query.search_scope, 'LEVEL');
    assert.deepEqual(query.args, { passnotrequired: true, admincount: true, disabled: true, ldapfilter: '(mail=*)', identity: 'a*', memberof: 'Domain Admins', department: 'IT' });
    assert.equal(await trigger.getAttribute('aria-label'), 'Search options, 9 active');
    assert.equal(new URL(page.url()).searchParams.get('ldapfilter'), '(mail=*)');
    await page.locator('#grid-refresh').click(); await page.locator('#grid-body tr[data-dn]').waitFor();
    assert.deepEqual(requests.at(-1).args, query.args);
    await page.locator('#grid-fields').click(); await page.locator('#fields-menu').getByLabel('department, Department', { exact: true }).check();
    await page.locator('#fields-menu').getByLabel(/^memberOf, Direct groups/).check();
    await page.locator('#fields-menu').getByRole('button', { name: 'Done', exact: true }).click();
    await page.locator('#grid-head').getByRole('button', { name: 'department', exact: true }).waitFor();
    await page.locator('#grid-body tr[data-dn]').waitFor();
    assert.deepEqual(requests.at(-1).args, query.args); assert.ok(requests.at(-1).properties.includes('department'));
    assert.ok(requests.at(-1).properties.includes('memberOf'));
    const group = page.locator('#grid-body').getByRole('button', { name: 'Domain Admins', exact: true });
    assert.equal(await group.getAttribute('title'), 'CN=Domain Admins,CN=Users,DC=example,DC=test');
    await trigger.click(); await menu.getByRole('button', { name: 'Clear', exact: true }).click();
    await page.locator('.toolbar__title').click();
    await trigger.click(); assert.equal(await menu.getByLabel('adminCount set', { exact: true }).isChecked(), true);
    fail = true;
    await menu.getByRole('button', { name: 'Apply', exact: true }).click();
    await page.getByRole('heading', { name: 'Cannot load users' }).waitFor();
    assert.equal(await trigger.isEnabled(), true);
    fail = false;
    await page.getByRole('button', { name: 'Retry', exact: true }).click(); await page.locator('#grid-body tr[data-dn]').waitFor();
    assert.deepEqual(requests.at(-1).args, query.args);
    await trigger.click(); await menu.getByRole('button', { name: 'Clear', exact: true }).click();
    await menu.getByRole('button', { name: 'Apply', exact: true }).click(); await page.locator('#grid-body tr[data-dn]').waitFor();
    assert.equal(requests.at(-1).args, undefined); assert.equal(requests.at(-1).searchbase, undefined);
    assert.equal(new URL(page.url()).searchParams.get('ldapfilter'), null);
    await page.goto(`${base}/users?ldapfilter=${encodeURIComponent('(adminCount=1)')}`);
    await page.locator('#grid-body tr[data-dn]').waitFor();
    assert.deepEqual(requests.at(-1).args, { ldapfilter: '(adminCount=1)' });
    assert.equal(await trigger.getAttribute('aria-label'), 'Search options, 1 active');
    await trigger.click(); assert.equal(await menu.getByLabel('LDAP filter', { exact: true }).inputValue(), '(adminCount=1)');
    await page.keyboard.press('Escape');
    await page.goto(`${base}/users?ldapfilter=adminCount=1`);
    await page.locator('#grid-body tr[data-dn]').waitFor();
    assert.equal(requests.at(-1).args, undefined);
    for (const colorScheme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme });
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: 844 }); await trigger.click(); await menu.locator('summary').click();
        const bounds = await menu.boundingBox(); assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        assert.ok(bounds.y + bounds.height <= 844);
        const applyBounds = await menu.getByRole('button', { name: 'Apply', exact: true }).boundingBox();
        assert.ok(applyBounds.y >= bounds.y && applyBounds.y + applyBounds.height <= 844);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        await page.screenshot({ path: `/tmp/pv-search-${colorScheme}-${width}.png` });
        await page.keyboard.press('Escape');
      }
    }
    assert.deepEqual(errors, []);
    console.log('PASS: explicit Apply, Escape/outside discard, CLI payloads, exclusive options, base/scope/filter, Fields and refresh retention, error/retry, Clear, linked LDAP filters, desktop/mobile light/dark bounds.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
