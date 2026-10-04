const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    for (const type of ['user', 'computer']) {
      const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      const record = { dn: `CN=Test account,CN=Users,${rootDN}`, attributes: {
        name: 'Test account', objectClass: type === 'computer' ? ['top', 'user', 'computer'] : ['top', 'user'], userAccountControl: 512,
      } };
      const writes = []; const errors = [];
      let response = false; let release;
      page.on('pageerror', (error) => errors.push(error.message));
      await page.route('**/api/**', async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol: 'LDAPS', username: 'tester', domain: 'example.test' } });
        if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN, domain: 'example.test' } });
        if (path.endsWith(`/set/domain${type}password`)) {
          writes.push({ path, data: route.request().postDataJSON() });
          await new Promise((resolve) => { release = resolve; });
          return route.fulfill({ json: response });
        }
        if (path.endsWith(`/get/domain${type}`) || path.endsWith('/get/domainobject')) return route.fulfill({ json: [record] });
        return route.fulfill({ json: [] });
      });
      await page.goto(`${base}/${type}s`);
      await page.locator('#grid-body tr[data-dn]').first().click();
      const action = page.getByRole('button', { name: type === 'computer' ? 'Reset computer account password…' : 'Reset password…', exact: true });
      await action.click();
      const dialog = page.getByRole('dialog');
      const password = dialog.getByLabel('New password', { exact: true });
      const confirmation = dialog.getByLabel('Confirm password', { exact: true });
      const submit = dialog.getByRole('button', { name: 'Reset password', exact: true });
      assert.equal(await password.evaluate((node) => node === document.activeElement), true);
      assert.equal(await dialog.getByText(record.dn, { exact: true }).count(), 1);
      assert.equal(await dialog.getByText(/may break the computer/).count(), type === 'computer' ? 1 : 0);
      await submit.click();
      assert.equal(writes.length, 0);
      await password.fill(' New password! ');
      await confirmation.fill('different');
      await submit.click();
      assert.equal(await dialog.getByRole('alert').textContent(), 'Passwords do not match.');
      assert.equal(writes.length, 0);
      await confirmation.fill(' New password! ');
      await dialog.getByLabel('Show passwords').check();
      assert.equal(await password.getAttribute('type'), 'text');
      assert.equal(await confirmation.getAttribute('type'), 'text');
      await dialog.getByLabel('Show passwords').uncheck();
      await submit.click();
      await page.waitForFunction(() => document.querySelector('dialog[open] form')?.getAttribute('aria-busy') === 'true');
      assert.equal(await submit.isDisabled(), true);
      await page.keyboard.press('Escape');
      assert.equal(await dialog.isVisible(), true);
      for (let attempt = 0; !release && attempt < 100; attempt++) await page.waitForTimeout(10);
      assert.ok(release);
      release();
      await dialog.getByRole('alert').waitFor();
      assert.match(await dialog.getByRole('alert').textContent(), /did not confirm/);
      assert.deepEqual(writes, [{ path: `/api/set/domain${type}password`, data: { identity: record.dn, accountpassword: ' New password! ' } }]);
      response = true; release = null;
      await submit.click();
      for (let attempt = 0; !release && attempt < 100; attempt++) await page.waitForTimeout(10);
      assert.ok(release);
      release();
      await dialog.waitFor({ state: 'detached' });
      await page.locator('.toast__text', { hasText: /^Password reset for Test account$/ }).waitFor();
      assert.equal(writes.length, 2);
      await action.click();
      assert.equal(await password.inputValue(), '');
      assert.equal(await confirmation.inputValue(), '');
      assert.equal(await password.getAttribute('type'), 'password');
      if (process.env.RESET_SCREENSHOT_DIR) {
        await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'light' });
        await page.screenshot({ animations: 'disabled', path: `${process.env.RESET_SCREENSHOT_DIR}/${type}-desktop.png` });
        await page.setViewportSize({ width: 390, height: 844 });
        await page.emulateMedia({ colorScheme: 'dark' });
        await page.screenshot({ animations: 'disabled', path: `${process.env.RESET_SCREENSHOT_DIR}/${type}-mobile.png` });
      }
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
      await dialog.waitFor({ state: 'detached' });
      assert.equal(await action.evaluate((node) => node === document.activeElement), true);
      assert.equal(writes.length, 2);
      assert.deepEqual(errors, []);
      await page.close();
    }
    console.log('Password reset browser checks passed');
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
