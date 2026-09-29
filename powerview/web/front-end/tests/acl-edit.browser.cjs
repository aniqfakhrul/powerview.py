const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const dn = `CN=Target,CN=Users,${rootDN}`;
const identity = { index: 1, ace: 'a'.repeat(64), dacl: 'b'.repeat(64) };
const ace = { RemovalIdentity: identity, ACEType: 'ACCESS_ALLOWED_OBJECT_ACE', ACEFlags: ['CONTAINER_INHERIT_ACE'], ACEFlagsValue: 2, AccessMask: ['ControlAccess'], AccessMaskValue: 0x01000100, SecurityIdentifier: 'Authenticated Users', RawSecurityIdentifier: 'S-1-5-11', ObjectAceType: 'Reset Password', ObjectAceTypeGuid: '00299570-246d-11d0-a768-00aa006e0529', InheritanceType: 'User' };

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = []; const writes = [];
    let fail = true; let reads = 0; let release;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith('/set/domainobjectacl')) {
        writes.push(route.request().postDataJSON());
        if (fail) return route.fulfill({ status: 400, json: { error: 'The DACL changed. Refresh Security and select the entry again.' } });
        await new Promise((resolve) => { release = resolve; });
        return route.fulfill({ json: true });
      }
      if (path.includes('/add/') || path.includes('/remove/')) throw new Error('Edit must not add or remove an ACE');
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
      if (path.endsWith('/get/domainobjectowner')) return route.fulfill({ json: [] });
      if (path.endsWith('/get/domainobjectacl')) {
        reads++;
        return route.fulfill({ json: [{ attributes: [ace, { ...ace, ACEFlagsValue: 16, ACEFlags: ['INHERITED_ACE'], RemovalIdentity: undefined }, { ...ace, ACEType: 'ACCESS_ALLOWED_CALLBACK_ACE' }] }] });
      }
      if (path.endsWith('/get/domainuser') || path.endsWith('/get/domainobject')) return route.fulfill({ json: [{ dn, attributes: { name: 'Target', objectClass: ['user'], userAccountControl: 512 } }] });
      return route.fulfill({ json: [] });
    });
    await page.goto(`${base}/users`);
    await page.locator('#grid-body tr[data-dn]').first().click();
    await page.getByRole('tab', { name: 'Security', exact: true }).click();
    const edit = page.getByRole('button', { name: 'Edit access entry for Authenticated Users', exact: true });
    await edit.waitFor();
    assert.equal(await edit.count(), 1);
    await edit.focus();
    await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog', { name: 'Edit access entry' });
    const mask = dialog.getByLabel('Access mask', { exact: true });
    assert.equal(await mask.inputValue(), '0x01000100');
    assert.equal(await dialog.getByLabel('Principal', { exact: true }).getAttribute('readonly'), '');
    assert.equal(await dialog.getByLabel('Container inherit', { exact: true }).isChecked(), true);
    await dialog.getByText('Permission bits', { exact: true }).click();
    await dialog.getByLabel('Generic read', { exact: true }).check();
    assert.equal(await mask.inputValue(), '0x81000100');
    await dialog.getByLabel('Generic read', { exact: true }).uncheck();
    assert.equal(await mask.inputValue(), '0x01000100');
    await dialog.getByLabel('Write DACL', { exact: true }).check();
    assert.equal(await mask.inputValue(), '0x01040100');
    await dialog.getByLabel('Access', { exact: true }).selectOption('denied');
    await dialog.getByLabel('Descendants only', { exact: true }).check();
    if (process.env.ACL_EDIT_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.ACL_EDIT_SCREENSHOT_DIR}/desktop.png` });
    await mask.fill('0x100000000');
    await dialog.getByRole('button', { name: 'Save changes' }).click();
    assert.equal(writes.length, 0);
    await mask.fill('0x01040100');
    await dialog.getByRole('button', { name: 'Save changes' }).click();
    await dialog.getByRole('alert').filter({ hasText: 'DACL changed' }).waitFor();
    assert.equal(await mask.inputValue(), '0x01040100');
    assert.deepEqual(writes[0], { targetidentity: dn, ace: identity, access_mask: 0x01040100, ace_type: 'denied', ace_flags: 10 });
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    fail = false;
    await edit.click();
    await page.setViewportSize({ width: 390, height: 844 });
    await mask.fill('0x00040000');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await dialog.evaluate((node) => Promise.all(node.getAnimations().map((animation) => animation.finished)));
    if (process.env.ACL_EDIT_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.ACL_EDIT_SCREENSHOT_DIR}/mobile.png` });
    const before = reads;
    await dialog.getByRole('button', { name: 'Save changes' }).click();
    await page.waitForFunction(() => document.querySelector('.acl-dialog button[type="submit"]').disabled);
    await page.keyboard.press('Escape');
    assert.equal(await dialog.isVisible(), true);
    assert.equal(await dialog.getByRole('button', { name: 'Cancel' }).isDisabled(), true);
    assert.equal(writes.length, 2);
    release();
    await dialog.waitFor({ state: 'detached' });
    await page.locator('.toast--success', { hasText: 'Access entry updated' }).waitFor();
    await page.waitForFunction(() => document.querySelectorAll('.security__edit').length === 1);
    assert.ok(reads > before);
    assert.deepEqual(errors, []);
    console.log('PASS: explicit ACE editing, preserved metadata, mask validation, stale error, single update request, busy guard, refresh and mobile layout.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
