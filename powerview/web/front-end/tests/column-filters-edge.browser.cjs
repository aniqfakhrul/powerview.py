/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';

async function mockDirectory(page, { users = [], computers = [], schemaGate = null } = {}) {
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
    if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
    if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
    if (path.endsWith('/schema/attributes')) {
      if (schemaGate) await schemaGate;
      return route.fulfill({ json: { available: true, class: 'user', attributes: [{ name: 'badPwdCount', kind: 'integer', singleValued: true }] } });
    }
    if (path.endsWith('/get/domainuser')) return route.fulfill({ json: users });
    if (path.endsWith('/get/domaincomputer')) return route.fulfill({ json: computers });
    throw new Error(`Unexpected API request: ${path}`);
  });
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const errors = [];
    const menuOf = (page) => page.locator('#column-filter');
    const labels = (page) => menuOf(page).locator('.fields-menu__list .fields-menu__label').allTextContents();

    {
      const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      page.on('pageerror', (error) => errors.push(error.message));
      let release;
      const schemaGate = new Promise((resolve) => { release = resolve; });
      await page.addInitScript(() => localStorage.setItem('powerview.users.columns', JSON.stringify(['account', 'attr:badPwdCount'])));
      await mockDirectory(page, { schemaGate, users: [
        { dn: `CN=A,${root}`, attributes: { name: 'A', sAMAccountName: 'a', badPwdCount: '0' } },
        { dn: `CN=B,${root}`, attributes: { name: 'B', sAMAccountName: 'b', badPwdCount: '3' } },
      ] });
      await page.goto(`${base}/users`);
      await page.locator('#grid-body tr[data-dn]').first().waitFor();
      const trigger = page.locator('th[data-key="attr:badPwdCount"] .column-filter-trigger');
      await trigger.click();
      assert.deepEqual(await labels(page), ['0', '3']);
      await menuOf(page).locator('.fields-menu__list input').first().uncheck();
      await page.keyboard.press('Escape');
      assert.equal(await page.locator('#grid-count').textContent(), '1 of 2 users');
      await page.locator('th[data-key="account"] .column-filter-trigger').click();
      await menuOf(page).locator('.fields-menu__list input').first().uncheck();
      assert.equal(await page.locator('#grid-count').textContent(), '0 of 2 users');
      release();
      await page.waitForFunction(() => document.querySelector('#grid-count').textContent === '1 of 2 users');
      assert.equal(await menuOf(page).isVisible(), true);
      assert.match(await page.locator('th[data-key="account"] .column-filter-trigger').getAttribute('class'), /is-active/);
      assert.doesNotMatch(await page.locator('th[data-key="attr:badPwdCount"] .column-filter-trigger').getAttribute('class'), /is-active/);
      await page.keyboard.press('Escape');
      await page.locator('th[data-key="attr:badPwdCount"] .column-filter-trigger').click();
      await menuOf(page).getByRole('combobox').selectOption('between');
      await menuOf(page).getByLabel('Maximum').fill('0');
      assert.equal(await page.locator('#grid-count').textContent(), '1 of 2 users');
      await page.close();
    }

    {
      const page = await browser.newPage({ viewport: { width: 844, height: 390 } });
      page.on('pageerror', (error) => errors.push(error.message));
      await mockDirectory(page, { users: Array.from({ length: 40 }, (_, index) => ({ dn: `CN=U${index},${root}`, attributes: { name: `U${index}`, sAMAccountName: `user${index}`, userAccountControl: 512 } })) });
      await page.goto(`${base}/users`);
      await page.locator('#grid-body tr[data-dn]').first().waitFor();
      await page.locator('th[data-key="account"] .column-filter-trigger').click();
      const box = await menuOf(page).boundingBox();
      assert.ok(box.y >= 0 && box.y + box.height <= 390, `menu ${box.y}..${box.y + box.height} exceeds 390`);
      const done = await menuOf(page).getByRole('button', { name: 'Done' }).boundingBox();
      assert.ok(done.y + done.height <= 390);
      const list = menuOf(page).locator('.fields-menu__list');
      assert.ok(await list.evaluate((node) => node.scrollHeight > node.clientHeight));
      await list.evaluate((node) => { node.scrollTop = node.scrollHeight; });
      await menuOf(page).getByText('user9', { exact: true }).click();
      assert.equal(await page.locator('#grid-count').textContent(), '39 of 40 users');
      await page.close();
    }

    {
      const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      page.on('pageerror', (error) => errors.push(error.message));
      await page.addInitScript(() => localStorage.setItem('powerview.computers.columns', JSON.stringify(['ipAddress'])));
      await mockDirectory(page, { computers: [
        { dn: `CN=WS1,${root}`, attributes: { name: 'WS1', IPAddress: ['10.0.0.1', '10.0.0.2'] } },
        { dn: `CN=WS2,${root}`, attributes: { name: 'WS2', IPAddress: ['10.0.0.2'] } },
        { dn: `CN=WS3,${root}`, attributes: { name: 'WS3' } },
      ] });
      await page.goto(`${base}/computers`);
      await page.locator('#grid-body tr[data-dn]').first().waitFor();
      assert.equal(await page.locator('#grid-body tr', { hasText: 'WS1' }).locator('td').last().innerText(), '10.0.0.1, 10.0.0.2');
      await page.locator('th[data-key="ipAddress"] .column-filter-trigger').click();
      assert.deepEqual(await labels(page), ['10.0.0.1', '10.0.0.2', '(Empty)']);
      assert.deepEqual(await menuOf(page).locator('.fields-menu__list .fields-menu__hint').allTextContents(), ['1', '2', '1']);
      await menuOf(page).locator('.column-filter__all input').uncheck();
      await menuOf(page).getByText('10.0.0.2', { exact: true }).click();
      assert.deepEqual((await page.locator('#grid-body tr[data-dn] .cell-name span').allTextContents()).sort(), ['WS1', 'WS2']);
      await page.close();
    }

    assert.deepEqual(errors, []);
    console.log('PASS: schema load drops an incompatible custom-column filter without errors, keeps other filters and the open menu, then offers a number range; short viewport keeps the menu and footer on screen with a scrolling list; multi-address IPAddress filters by individual address.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
