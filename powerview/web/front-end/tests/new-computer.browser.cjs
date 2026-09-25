/** All API traffic is mocked; this suite never creates directory objects. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage();
    const writes = []; const errors = []; let protocol = 'LDAPS'; let accepted = false; let failList = false; let release;
    const records = []; const rootDN = 'DC=example,DC=test';
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol } });
      if (path.endsWith('/schema/attributes')) return route.fulfill({ json: { available: false } });
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
      if (path.endsWith('/get/domaincomputer')) return failList ? route.fulfill({ status: 400, json: { error: 'Refresh failed' } }) : route.fulfill({ json: records });
      if (path.endsWith('/add/domaincomputer')) {
        const data = route.request().postDataJSON(); writes.push(data);
        if (accepted) {
          await new Promise((resolve) => { release = resolve; });
          records.push({ dn: `CN=${data.computer_name},${data.basedn}`, attributes: { name: data.computer_name, userAccountControl: 4096 } });
        }
        return route.fulfill({ json: accepted });
      }
      throw new Error(`Unexpected API request: ${path}`);
    });
    await page.goto(`${base}/computers`);
    const dialog = page.locator('#computer-dialog');
    await page.getByRole('button', { name: 'Add computer', exact: true }).click();
    assert.equal(await dialog.getByLabel('Container', { exact: true }).inputValue(), `CN=Computers,${rootDN}`);
    await dialog.getByLabel('Name', { exact: true }).fill('Bad,Name');
    await dialog.getByLabel('Password', { exact: true }).fill('Test-only-password!');
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await page.locator('#computer-error').waitFor(); assert.equal(writes.length, 0);
    await dialog.getByLabel('Name', { exact: true }).fill('WS-NEW$');
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#computer-error').textContent.includes('did not confirm'));
    assert.deepEqual(writes[0], { computer_name: 'WS-NEW', computer_pass: 'Test-only-password!', basedn: `CN=Computers,${rootDN}` });
    assert.equal(await dialog.getByLabel('Password', { exact: true }).inputValue(), 'Test-only-password!');
    protocol = 'LDAP';
    await dialog.getByLabel('Container', { exact: true }).fill(`OU=Servers,${rootDN}`);
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#computer-error').textContent.includes('requires an LDAPS'));
    assert.equal(writes.length, 1);
    protocol = 'LDAPS'; accepted = true;
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#computer-form').getAttribute('aria-busy') === 'true');
    await page.keyboard.press('Escape'); assert.equal(await dialog.isVisible(), true);
    assert.equal(await dialog.getByRole('button', { name: 'Create', exact: true }).isDisabled(), true);
    while (!release) await page.waitForTimeout(10);
    release();
    await page.locator('#grid-body tr[data-dn]').waitFor();
    assert.equal(await dialog.isVisible(), false);
    assert.equal(await page.locator('#grid-filter').inputValue(), 'WS-NEW');
    assert.equal(writes.length, 2);
    assert.equal(await page.locator('#computer-password').inputValue(), '');
    await page.getByRole('button', { name: 'Add computer', exact: true }).click();
    await dialog.getByLabel('Name', { exact: true }).fill('WS-SECOND');
    await dialog.getByLabel('Password', { exact: true }).fill('Another-test-password!');
    failList = true; release = null;
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    while (!release) await page.waitForTimeout(10);
    release();
    await page.getByRole('heading', { name: 'Cannot load computers' }).waitFor();
    assert.equal(await dialog.isVisible(), false);
    for (const colorScheme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme }); await page.setViewportSize({ width: 390, height: 844 });
      await page.getByRole('button', { name: 'Add computer', exact: true }).click();
      const rect = await dialog.boundingBox(); assert.ok(rect.x >= 0 && rect.x + rect.width <= 390);
      await page.screenshot({ animations: 'disabled', path: `/tmp/new-computer-${colorScheme}.png` });
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    }
    assert.deepEqual(errors, []);
    console.log('PASS: validation, exact computer payload, failure preserves inputs, custom-container transport guard, busy protection, create refresh/filter/toast flow, password clearing, failed refresh, mobile themes.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
