const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const dn = `CN=Target,CN=Users,${rootDN}`;
const principalDN = `CN=Operators,CN=Users,${rootDN}`;

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const writes = []; const reads = []; const errors = [];
    let response = false; let release; let removing = false; let received;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      const body = route.request().postDataJSON();
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
      if (path.endsWith('/add/domainobjectacl') || path.endsWith('/remove/domainobjectacl')) {
        writes.push(body);
        assert.equal(path.endsWith('/remove/domainobjectacl'), removing);
        await new Promise((resolve) => { release = resolve; received?.(); });
        return route.fulfill({ json: response });
      }
      if (path.endsWith('/get/domainobjectowner')) return route.fulfill({ json: [{ attributes: { Owner: 'Administrators (S-1-5-32-544)' } }] });
      if (path.endsWith('/get/domainobjectacl')) {
        reads.push(body);
        return route.fulfill({ json: [{ attributes: [{ ACEType: 'ACCESS_ALLOWED_OBJECT_ACE', ACEFlags: [], ACEFlagsValue: 0, AccessMask: ['ControlAccess'], AccessMaskValue: 256, RawSecurityIdentifier: 'S-1-5-11', SecurityIdentifier: 'Authenticated Users', ObjectAceType: 'Reset Password', ObjectAceTypeGuid: '00299570-246d-11d0-a768-00aa006e0529', ObjectAceFlagsValue: 1 }] }] });
      }
      if (path.endsWith('/get/domainobject') && body.ldap_filter) {
        assert.match(body.ldap_filter, /objectSid=\*/);
        return route.fulfill({ json: [{ dn: principalDN, attributes: { name: 'Operators', objectClass: ['group'] } }] });
      }
      if (path.endsWith('/get/domainuser') || path.endsWith('/get/domainobject')) {
        return route.fulfill({ json: [{ dn, attributes: { name: 'Target', objectClass: ['user'], userAccountControl: 512 } }] });
      }
      return route.fulfill({ json: [] });
    });
    await page.goto(`${base}/users`);
    await page.locator('#grid-body tr[data-dn]').first().click();
    await page.getByRole('tab', { name: 'Security', exact: true }).click();
    const add = page.getByRole('button', { name: 'Add access entry', exact: true });
    await add.click();
    const dialog = page.getByRole('dialog', { name: 'Add access entry', exact: true });
    const principal = dialog.getByRole('combobox', { name: 'Principal', exact: true });
    const rights = dialog.getByLabel('Rights', { exact: true });
    const access = dialog.getByLabel('Access', { exact: true });
    const submit = dialog.getByRole('button', { name: 'Add entry', exact: true });
    assert.equal(await rights.inputValue(), '');
    assert.equal(await dialog.getByText(dn, { exact: true }).count(), 1);
    await submit.click();
    assert.equal(writes.length, 0);
    await principal.fill('Operators');
    await dialog.getByRole('option', { name: /Operators/ }).click();
    assert.equal(await principal.inputValue(), principalDN);
    await rights.selectOption('custom');
    await dialog.getByLabel('Rights GUID', { exact: true }).fill('invalid');
    await submit.click();
    assert.match(await dialog.getByRole('alert').textContent(), /Enter a GUID/);
    assert.equal(writes.length, 0);
    await rights.selectOption('immutable');
    assert.equal(await access.inputValue(), 'denied');
    assert.equal(await access.isDisabled(), true);
    await dialog.getByLabel('Applies to').selectOption('descendants');
    await submit.click();
    await page.waitForFunction(() => document.querySelector('dialog[open] form')?.getAttribute('aria-busy') === 'true');
    await page.keyboard.press('Escape');
    assert.equal(await dialog.isVisible(), true);
    assert.equal(await submit.isDisabled(), true);
    assert.deepEqual(writes[0], { targetidentity: dn, principalidentity: principalDN, rights: 'immutable', ace_type: 'denied', inheritance: true });
    release();
    await dialog.getByRole('alert').waitFor();
    assert.match(await dialog.getByRole('alert').textContent(), /did not confirm/);
    assert.equal(await principal.inputValue(), principalDN);
    assert.equal(await access.isDisabled(), true);
    assert.equal(writes.length, 1);
    response = true;
    await rights.selectOption('custom');
    const guid = '00299570-246D-11D0-A768-00AA006E0529';
    await dialog.getByLabel('Rights GUID', { exact: true }).fill(guid);
    await access.selectOption('allowed');
    await submit.click();
    await page.waitForFunction(() => document.querySelector('dialog[open] form')?.getAttribute('aria-busy') === 'true');
    assert.deepEqual(writes[1], { targetidentity: dn, principalidentity: principalDN, rights: 'fullcontrol', rights_guid: guid.toLowerCase(), ace_type: 'allowed', inheritance: true });
    release();
    await dialog.waitFor({ state: 'hidden' });
    await add.waitFor();
    assert.equal(reads.at(-1).no_cache, true);
    assert.equal(await page.getByRole('tab', { name: 'Security', exact: true }).getAttribute('aria-selected'), 'true');
    for (const preset of ['fullcontrol', 'resetpassword', 'writemembers', 'dcsync']) {
      await add.click();
      await principal.fill('S-1-5-11');
      await rights.selectOption(preset);
      await submit.click();
      await page.waitForFunction(() => document.querySelector('dialog[open] form')?.getAttribute('aria-busy') === 'true');
      assert.deepEqual(writes.at(-1), { targetidentity: dn, principalidentity: 'S-1-5-11', rights: preset, ace_type: 'allowed', inheritance: false });
      release();
      await dialog.waitFor({ state: 'hidden' });
      await add.waitFor();
    }
    removing = true;
    const row = page.locator('.security__row').first();
    const remove = row.getByRole('button', { name: 'Remove access entry for Authenticated Users', exact: true });
    await row.hover();
    assert.equal(await remove.evaluate((node) => getComputedStyle(node).opacity), '1');
    await remove.focus();
    await page.keyboard.press('Enter');
    const removal = page.getByRole('dialog', { name: 'Remove access entry?', exact: true });
    assert.match(await removal.textContent(), /Identical matching entries/);
    assert.equal(await row.getAttribute('aria-expanded'), 'false');
    await removal.getByRole('button', { name: 'Cancel', exact: true }).click();
    assert.equal(writes.length, 6);
    response = false;
    await remove.click();
    const arrival = new Promise((resolve) => { received = resolve; });
    await removal.getByRole('button', { name: 'Remove', exact: true }).click();
    await arrival;
    await page.waitForFunction(() => document.querySelector('.security__remove')?.disabled);
    assert.deepEqual(writes.at(-1), { targetidentity: dn, principalidentity: 'S-1-5-11', rights: 'fullcontrol', rights_guid: '00299570-246d-11d0-a768-00aa006e0529', ace_type: 'allowed', inheritance: false });
    release();
    await page.locator('.toast__text').filter({ hasText: 'PowerView did not confirm this change' }).waitFor();
    assert.equal(await row.isVisible(), true);
    response = true;
    await remove.click();
    const retryArrival = new Promise((resolve) => { received = resolve; });
    await removal.getByRole('button', { name: 'Remove', exact: true }).click();
    await retryArrival;
    await page.waitForFunction(() => document.querySelector('.security__remove')?.disabled);
    const freshRead = page.waitForRequest((request) => request.url().endsWith('/get/domainobjectacl') && request.postDataJSON().no_cache === true);
    release();
    await freshRead;
    await page.locator('.toast__text').filter({ hasText: /^Access entry removed$/ }).waitFor();
    await add.waitFor();
    assert.equal(reads.at(-1).no_cache, true);
    removing = false;
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 844 });
      for (const colorScheme of ['light', 'dark']) {
        await page.emulateMedia({ colorScheme });
        await row.hover();
        if (process.env.ACL_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.ACL_SCREENSHOT_DIR}/security-${width}-${colorScheme}.png`, animations: 'disabled' });
        await add.click();
        await rights.selectOption('custom');
        const bounds = await dialog.boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        assert.equal(await dialog.evaluate((node) => node.scrollWidth <= node.clientWidth), true);
        if (process.env.ACL_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.ACL_SCREENSHOT_DIR}/acl-${width}-${colorScheme}.png`, animations: 'disabled' });
        await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
        assert.equal(await add.evaluate((node) => document.activeElement === node), true);
      }
    }
    assert.equal(writes.length, 8);
    assert.deepEqual(errors, []);
    console.log('PASS: ACL principal lookup, required rights, GUID validation, preset payloads, forced Deny, inheritance, failure preservation, busy guards, fresh Security reads, cancellation and responsive themes.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
