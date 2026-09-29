/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const users = Array.from({ length: 3 }, (_, index) => ({ dn: `CN=User ${index},${root}`, attributes: {
  name: `User ${index}`, sAMAccountName: `user${index}`, userAccountControl: 512,
  description: index === 1 ? 'A deliberately long description that needs a much wider column than the default one' : 'Fixture',
} }));
const record = (dn) => ({ dn, attributes: {
  name: 'User 0', objectClass: ['top', 'user'], description: '24/09/2026 notes',
  whenCreated: '24/09/2026 12:18:10 (2 days ago)', whenChanged: '20260924121810.0Z',
} });

async function mockDirectory(page, { gate = null, fail = false } = {}) {
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = route.request().postDataJSON();
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
    if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
    if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
    if (path.endsWith('/schema/attributes')) return route.fulfill({ json: { available: false } });
    if (path.endsWith('/get/domainuser')) {
      if (gate) await gate;
      return fail ? route.fulfill({ status: 400, json: { error: 'Search failed (test)' } }) : route.fulfill({ json: users });
    }
    if (path.endsWith('/get/domainobject')) return route.fulfill({ json: [record(data.searchbase)] });
    throw new Error(`Unexpected API request: ${path}`);
  });
}

const widths = (page) => page.$$eval('#grid-head th[data-key]', (cells) => Object.fromEntries(cells.map((cell) => [cell.dataset.key, Math.round(cell.getBoundingClientRect().width)])));
const visibleTriggers = (page) => page.$$eval('#grid-head .column-filter-trigger', (items) => items.filter((item) => getComputedStyle(item).visibility !== 'hidden' && getComputedStyle(item).opacity !== '0').length);

async function drag(page, key, distance) {
  const box = await page.locator(`th[data-key="${key}"] .column-resizer`).boundingBox();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width / 2 + distance, box.y + box.height / 2, { steps: 5 });
  await page.mouse.up();
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const errors = [];

    {
      const page = await browser.newPage({ viewport: { width: 1440, height: 800 } });
      page.on('pageerror', (error) => errors.push(error.message));
      let release;
      await mockDirectory(page, { gate: new Promise((resolve) => { release = resolve; }) });
      await page.goto(`${base}/users`);
      await page.locator('th[data-key="status"]').hover();
      assert.equal(await visibleTriggers(page), 0, 'disabled filter triggers show while loading');
      release();
      await page.locator('#grid-body tr[data-dn]').first().waitFor();
      await page.locator('th[data-key="status"]').hover();
      assert.equal(await visibleTriggers(page), 1);
      await page.close();
    }

    {
      const page = await browser.newPage({ viewport: { width: 1440, height: 800 } });
      page.on('pageerror', (error) => errors.push(error.message));
      await mockDirectory(page, { fail: true });
      await page.goto(`${base}/users`);
      await page.getByRole('heading', { name: 'Cannot load users' }).waitFor();
      await page.locator('th[data-key="description"]').hover();
      assert.equal(await visibleTriggers(page), 0, 'disabled filter triggers show after a failed load');
      await page.close();
    }

    {
      const page = await browser.newPage({ viewport: { width: 1440, height: 800 } });
      page.on('pageerror', (error) => errors.push(error.message));
      await mockDirectory(page);
      await page.goto(`${base}/users`);
      await page.locator('#grid-body tr[data-dn]').first().waitFor();
      const defaults = await widths(page);
      await drag(page, 'description', -100);
      assert.ok(Math.abs((await widths(page)).description - (defaults.description - 100)) <= 2);
      assert.equal(await page.locator('th[data-key="description"]').getAttribute('aria-sort'), null);
      await page.reload();
      await page.locator('#grid-body tr[data-dn]').first().waitFor();
      assert.ok(Math.abs((await widths(page)).description - (defaults.description - 100)) <= 2, 'column width was not remembered');

      await page.locator('th[data-key="description"] .column-resizer').dblclick();
      assert.ok((await widths(page)).description > defaults.description);
      assert.equal(await page.locator('th[data-key="description"]').getAttribute('aria-sort'), null);
      assert.ok(await page.$$eval('#grid-body tr[data-dn]', (rows) => {
        const index = [...document.querySelectorAll('#grid-head th')].findIndex((cell) => cell.dataset.key === 'description');
        return rows.every((row) => row.cells[index].scrollWidth <= row.cells[index].clientWidth);
      }), 'fitted column still truncates a value');

      await drag(page, 'name', 80);
      assert.ok((await widths(page)).name > defaults.name);
      await page.locator('#grid-fields').click();
      await page.getByRole('button', { name: 'Reset to default' }).click();
      await page.getByRole('button', { name: 'Done' }).click();
      await page.locator('#fields-menu').waitFor({ state: 'hidden' });
      await page.waitForFunction((width) => Math.round(document.querySelector('th[data-key="name"]').getBoundingClientRect().width) === width, defaults.name);
      assert.deepEqual(await widths(page), defaults);
      await page.close();
    }

    {
      const page = await browser.newPage({ viewport: { width: 1440, height: 800 } });
      page.on('pageerror', (error) => errors.push(error.message));
      await page.addInitScript(() => localStorage.setItem('powerview.users.columns', JSON.stringify(['groups'])));
      await mockDirectory(page);
      await page.goto(`${base}/users`);
      await page.locator('#grid-body tr[data-dn]').first().waitFor();
      const header = page.locator('th[data-key="groups"]');
      const natural = await header.locator('.column-sort__label').evaluate((label) => {
        const range = document.createRange();
        range.selectNodeContents(label);
        return range.getBoundingClientRect().width;
      });
      assert.ok(parseFloat(await header.evaluate((th) => th.style.width)) > 130, 'a spare-width grid skipped fitting a long header');
      assert.ok(natural > 60);
      await page.close();
    }

    {
      const page = await browser.newPage({ viewport: { width: 1440, height: 800 }, colorScheme: 'dark' });
      page.on('pageerror', (error) => errors.push(error.message));
      await mockDirectory(page);
      await page.goto(`${base}/users`);
      const rows = page.locator('#grid-body tr[data-dn]');
      await rows.first().waitFor();
      await rows.first().click();
      await page.keyboard.press('ArrowDown');
      const paint = await page.evaluate(() => {
        const resolve = (value) => {
          const probe = document.createElement('div');
          probe.style.background = value;
          document.body.append(probe);
          const color = getComputedStyle(probe).backgroundColor;
          probe.remove();
          return color;
        };
        const [selected, focused] = document.querySelectorAll('#grid-body tr[data-dn]');
        const cell = (row) => getComputedStyle(row.cells[2]);
        return {
          selected: cell(selected).backgroundColor, selectedText: cell(selected).color, focused: cell(focused).backgroundColor, ring: cell(focused).boxShadow,
          selectionFocus: resolve('var(--color-selection-focus)'), selectionText: resolve('var(--color-selection-text)'),
          surface: resolve('var(--color-surface)'), accent: resolve('var(--color-accent)'),
        };
      });
      assert.equal(paint.selected, paint.selectionFocus);
      assert.equal(paint.selectedText, 'rgb(255, 255, 255)');
      assert.equal(paint.selectionText, 'rgb(255, 255, 255)');
      assert.notEqual(paint.focused, paint.selectionFocus, 'keyboard focus looks like selection');
      assert.ok(paint.ring.includes(paint.accent), 'focused row has no accent ring');

      const panel = page.locator('#object-panel');
      const value = (name) => panel.locator(`.property-grid tbody tr[data-name="${name.toLowerCase()}"] td .value`);
      await value('whenCreated').waitFor();
      const expected = await page.evaluate(() => new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(Date.UTC(2026, 8, 24, 12, 18, 10)));
      assert.equal(await value('whenCreated').evaluate((node) => node.firstChild.textContent), expected);
      assert.equal(await value('whenCreated').locator('.value__note').textContent(), '2 days ago');
      assert.equal(await value('whenCreated').getAttribute('title'), '24/09/2026 12:18:10 (2 days ago)');
      assert.equal(await value('whenChanged').textContent(), expected);
      assert.equal(await value('description').textContent(), '24/09/2026 notes');
      assert.equal(await panel.locator('.property-grid thead th').nth(2).textContent(), 'Actions');
      await page.close();
    }

    assert.deepEqual(errors, []);
    console.log('PASS: filter triggers stay hidden while loading and after errors, column drag resize without sorting, remembered widths, double-click fits content, Reset to default restores widths, dark selection distinct from keyboard focus, property-grid times in the grid date format with relative note and raw title, named actions header.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
