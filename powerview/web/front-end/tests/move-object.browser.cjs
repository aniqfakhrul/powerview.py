const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const origin = `OU=People,${root}`;
const destination = `OU=Staff,${root}`;
const rdn = 'CN=Last\\, First+UID=123';
const initialDN = `${rdn},${origin}`;

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    let currentDN = initialDN;
    let succeed = false; let release; let received;
    const writes = []; const errors = [];
    const record = () => ({ dn: currentDN, attributes: { name: 'Last, First', distinguishedName: currentDN, objectClass: ['user'], userAccountControl: 512 } });
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      const body = route.request().postDataJSON();
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root, `CN=Configuration,${root}`] } } });
      if (path.endsWith('/set/domainobjectdn')) {
        writes.push(body);
        await new Promise((resolve) => { release = resolve; received(); });
        if (succeed) currentDN = `${rdn},${body.destination_dn}`;
        return route.fulfill({ json: succeed });
      }
      if (path.endsWith('/get/domainuser')) return route.fulfill({ json: [record()] });
      if (path.endsWith('/get/domainobject')) {
        return route.fulfill({ json: body.searchbase === currentDN ? [record()] : [{ dn: body.searchbase, attributes: { name: 'Container', distinguishedName: body.searchbase, objectClass: body.searchbase === root ? ['domainDNS'] : ['organizationalUnit'] } }] });
      }
      return route.fulfill({ json: [] });
    });
    await page.goto(`${base}/users`);
    await page.locator('#grid-body tr[data-dn]').first().click();
    const action = page.getByRole('button', { name: 'Move object', exact: true });
    await action.click();
    const dialog = page.getByRole('dialog', { name: 'Move Last, First', exact: true });
    const target = dialog.getByRole('textbox', { name: 'Destination container', exact: true });
    const submit = dialog.getByRole('button', { name: 'Move', exact: true });
    assert.equal(await target.inputValue(), origin);
    for (const [dn, message] of [[origin, 'different container'], [initialDN, 'into itself'], [`OU=Child,${initialDN}`, 'into itself'], [`CN=Configuration,${root}`, 'same naming context']]) {
      await target.fill(dn);
      await submit.click();
      await dialog.getByRole('alert').filter({ hasText: message }).waitFor();
      assert.equal(writes.length, 0);
    }
    await target.fill(destination);
    let arrival = new Promise((resolve) => { received = resolve; });
    await submit.click();
    await arrival;
    await page.keyboard.press('Escape');
    assert.equal(await dialog.isVisible(), true);
    assert.equal(await submit.isDisabled(), true);
    assert.deepEqual(writes[0], { identity: initialDN, destination_dn: destination, searchbase: root });
    release();
    await dialog.getByRole('alert').filter({ hasText: 'did not confirm' }).waitFor();
    assert.equal(await target.inputValue(), destination);
    succeed = true;
    arrival = new Promise((resolve) => { received = resolve; });
    await submit.click();
    await arrival;
    release();
    await dialog.waitFor({ state: 'hidden' });
    await page.locator('#grid-body tr[data-dn]').first().waitFor();
    await page.locator('[data-panel-body] .property-grid').waitFor();
    assert.equal(new URL(page.url()).searchParams.get('dn'), `${rdn},${destination}`);
    assert.equal(new URL(await page.locator('#panel-explorer').getAttribute('href')).searchParams.get('dn'), currentDN);
    assert.equal(await page.locator('#grid-body tr[data-dn]').first().getAttribute('data-dn'), currentDN);
    assert.equal(await page.locator('[data-panel-body] tr[data-name="distinguishedname"] td').first().textContent(), currentDN);
    await page.setViewportSize({ width: 390, height: 844 });
    await action.click();
    const bounds = await dialog.boundingBox();
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 390);
    if (process.env.MOVE_SCREENSHOT) await page.screenshot({ path: process.env.MOVE_SCREENSHOT, animations: 'disabled' });
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    assert.equal(await action.evaluate((node) => document.activeElement === node), true);
    assert.equal(writes.length, 2);
    assert.deepEqual(errors, []);
    console.log('PASS: DN move payload, escaped/multivalued RDN, invalid destinations, failed-write preservation, busy guard, new DN navigation, list refresh, mobile and focus restoration.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
