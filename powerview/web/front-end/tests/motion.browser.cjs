const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const capture = process.env.MOTION_SCREENSHOT_DIR;
const root = 'DC=example,DC=test';
const object = { dn: `CN=Alice,${root}`, attributes: { name: 'Alice', objectClass: ['user'], description: 'Motion fixture' } };
const endpoints = { users: 'domainuser', computers: 'domaincomputer', groups: 'domaingroup', dns: 'domaindnszone', ca: 'domaincatemplate', ou: 'domainou', gpo: 'domaingpo', pathfinder: 'domainobjectacl' };

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    if (capture) await fs.mkdir(capture, { recursive: true });
    for (const [name, endpoint] of Object.entries(endpoints)) {
      const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      const errors = [];
      page.on('pageerror', (error) => errors.push(error.message));
      let release;
      const gate = new Promise((resolve) => { release = resolve; });
      await page.route('**/api/**', async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path.endsWith(`/get/${endpoint}`)) { await gate; return route.fulfill({ json: [] }); }
        if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
        if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
        if (path.endsWith('/schema/attributes')) return route.fulfill({ json: { available: false } });
        if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
        return route.fulfill({ json: [] });
      });
      await page.goto(`${base}/${name}`);
      if (name === 'pathfinder') {
        assert.equal(await page.locator('.loading-row').count(), 0);
        await page.locator('#pathfinder-target').fill('Alice');
        await page.locator('#pathfinder-find').click();
      }
      await page.locator('.loading-row').first().waitFor();
      assert.equal(await page.locator('#grid-scroll').getAttribute('aria-busy'), 'true');
      assert.equal(await page.locator('.loading-row').count(), 8);
      assert.equal(await page.locator('.loading-row').first().getAttribute('aria-hidden'), 'true');
      assert.equal(await page.locator('.loading-row').first().evaluate((row) => getComputedStyle(row).animationName), 'loading-breathe');
      if (capture && ['users', 'gpo'].includes(name)) {
        await page.emulateMedia({ colorScheme: name === 'gpo' ? 'dark' : 'light' });
        await page.screenshot({ path: `${capture}/${name}-loading-desktop.png`, animations: 'disabled' });
      }
      await page.emulateMedia({ reducedMotion: 'reduce' });
      assert.equal(await page.locator('.loading-row').first().evaluate((row) => getComputedStyle(row).animationName), 'none');
      if (name === 'pathfinder') {
        await page.setViewportSize({ width: 390, height: 844 });
        if (capture) await page.screenshot({ path: `${capture}/pathfinder-loading-mobile.png`, animations: 'disabled' });
        await page.locator('#pathfinder-cancel').click();
        release();
        await page.waitForTimeout(300);
        assert.equal(await page.locator('.loading-row').count(), 0);
        assert.equal(await page.locator('#grid-scroll').getAttribute('aria-busy'), 'false');
        await page.getByText('Search cancelled', { exact: true }).waitFor();
      } else {
        release();
        await page.waitForFunction(() => document.querySelector('#grid-scroll').getAttribute('aria-busy') === 'false');
        assert.equal(await page.locator('.loading-row').count(), 0);
        assert.equal(await page.locator('#grid-refresh').isDisabled(), false);
      }
      assert.deepEqual(errors, []);
      await page.close();
    }

    for (const name of ['explorer', 'dashboard']) {
      const page = await browser.newPage({ viewport: { width: name === 'dashboard' ? 390 : 1440, height: 900 } });
      let release;
      let releaseDomain;
      const gate = new Promise((resolve) => { release = resolve; });
      const domainGate = new Promise((resolve) => { releaseDomain = resolve; });
      await page.route('**/api/**', async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (path.includes('/dashboard/')) { await (path.includes('/dashboard/domain') ? domainGate : gate); return route.fulfill({ status: 400, json: { error: 'Fixture directory unavailable' } }); }
        if (path.endsWith('/get/domainobject')) { await gate; return route.fulfill({ json: [object] }); }
        if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
        if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
        return route.fulfill({ json: { status: 'OK', available: false } });
      });
      await page.goto(`${base}/${name === 'explorer' ? `?dn=${encodeURIComponent(object.dn)}` : name}`);
      const skeleton = page.locator(name === 'explorer' ? '.skeleton:visible' : '.loading-row').first();
      await skeleton.waitFor();
      if (capture) await page.screenshot({ path: `${capture}/${name}-loading.png`, animations: 'disabled' });
      await page.emulateMedia({ reducedMotion: 'reduce' });
      assert.equal(await skeleton.evaluate((node) => getComputedStyle(node).animationName), 'none');
      if (name === 'dashboard') {
        assert.equal(await page.locator('#dashboard').getAttribute('aria-busy'), null);
        assert.equal(await page.locator('.dashboard__table').getAttribute('aria-busy'), 'true');
        for (const id of ['dashboard-policy', 'dashboard-systems', 'dashboard-controllers', 'dashboard-trust-list']) {
          assert.equal(await page.locator(`#${id} .loading-row`).count() > 0, true, id);
          assert.equal(await page.locator(`#${id}`).getAttribute('aria-busy'), 'true', id);
        }
        assert.equal(await page.locator('#dashboard-inventory [data-count] .loading-bar').count(), 6);
        assert.equal(await page.locator('.dashboard__signal-count .loading-bar').count(), 10);
        assert.doesNotMatch(await page.locator('.dashboard__scroll').innerText(), /Reading|Waiting for|Loading…/);
        releaseDomain();
        await page.locator('#dashboard-policy', { hasText: 'Domain policy unavailable' }).waitFor();
        assert.equal(await page.locator('#dashboard-policy').getAttribute('aria-busy'), 'false');
        assert.equal(await page.locator('#dashboard-systems .loading-row').count() > 0, true);
      } else releaseDomain();
      release();
      await skeleton.waitFor({ state: 'detached' });
      if (name === 'dashboard') {
        await page.waitForFunction(() => document.querySelector('.dashboard__table').getAttribute('aria-busy') === 'false');
        assert.equal(await page.locator('.dashboard__scroll .loading-row, .dashboard__scroll .loading-bar').count(), 0);
        assert.equal(await page.locator('.dashboard__scroll [aria-busy="true"]').count(), 0);
        assert.match(await page.locator('#dashboard-systems').innerText(), /Computer inventory unavailable/);
        assert.equal(await page.locator('[data-count="users"]').textContent(), '—');
      }
      await page.close();
    }

    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.route('**/api/**', (route) => {
      const path = new URL(route.request().url()).pathname;
      const data = path.endsWith('/get/domaininfo') ? { root_dn: root }
        : path.endsWith('/server/info') ? { raw: { namingContexts: [root] } }
          : path.endsWith('/get/domainuser') || path.endsWith('/get/domainobject') ? [object]
            : { status: 'OK', available: false };
      return route.fulfill({ json: data });
    });
    await page.goto(`${base}/users`);
    await page.locator('#grid-body tr[data-key]').first().click();
    await page.locator('#object-panel .property-grid').waitFor();
    assert.equal(await page.locator('#object-panel').evaluate((panel) => getComputedStyle(panel).animationName), 'panel-enter');
    await page.locator('#panel-close').click();
    await page.locator('#grid-fields').click();
    assert.equal(await page.locator('#fields-menu').evaluate((menu) => getComputedStyle(menu).animationName), 'menu-enter');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(await page.locator('#fields-menu').evaluate((menu) => getComputedStyle(menu).animationName), 'none');
    await page.keyboard.press('Escape');
    await page.locator('#grid-body tr[data-key]').first().click();
    assert.equal(await page.locator('#object-panel').evaluate((panel) => getComputedStyle(panel).animationName), 'none');
    await page.locator('#object-panel .property-grid').waitFor();
    if (capture) await page.screenshot({ path: `${capture}/users-details-desktop.png`, animations: 'disabled' });

    await page.emulateMedia({ reducedMotion: 'no-preference' });
    const tabs = page.locator('#object-panel [role="tablist"]');
    await tabs.getByRole('tab', { name: /^Member of/ }).click();
    const indicator = tabs.locator('.panel-tabs__indicator');
    assert.equal(await indicator.evaluate((node) => getComputedStyle(node).transitionDuration), '0.16s');
    await page.waitForTimeout(200);
    const aligned = () => tabs.evaluate((list) => {
      const tab = list.querySelector('[aria-selected="true"]');
      const line = list.querySelector('.panel-tabs__indicator').getBoundingClientRect();
      const box = tab.getBoundingClientRect();
      const style = getComputedStyle(tab);
      return Math.abs(line.left - box.left - parseFloat(style.paddingLeft)) < 1
        && Math.abs(line.right - box.right + parseFloat(style.paddingRight)) < 1;
    });
    assert.equal(await aligned(), true);
    if (capture) await page.screenshot({ path: `${capture}/tabs-desktop.png`, animations: 'disabled' });
    await page.keyboard.press('Home');
    await page.keyboard.press('End');
    await page.keyboard.press('Home');
    await page.waitForTimeout(200);
    assert.equal(await aligned(), true);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await tabs.getByRole('tab', { name: /^Member of/ }).click();
    assert.equal(await indicator.evaluate((node) => getComputedStyle(node).transitionDuration), '0s');
    assert.equal(await aligned(), true);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(100);
    assert.equal(await aligned(), true);

    if (capture) await page.screenshot({ path: `${capture}/tabs-mobile.png`, animations: 'disabled' });

    const timing = await page.evaluate(async () => {
      const { beginLoading } = await import('/static/js/components/loading.js');
      const host = document.createElement('div');
      document.body.append(host);
      let delayed = 0;
      const finish = beginLoading(host, { onDelay: () => { delayed += 1; } });
      finish();
      const controller = new AbortController();
      beginLoading(host, { signal: controller.signal, onDelay: () => { delayed += 1; } });
      controller.abort();
      await new Promise((resolve) => setTimeout(resolve, 250));
      const result = { delayed, busy: host.getAttribute('aria-busy'), loading: host.classList.contains('is-loading-delayed') };
      host.remove();
      return result;
    });
    assert.deepEqual(timing, { delayed: 0, busy: 'false', loading: false });
    await page.close();
    console.log('PASS: all eight grids delay skeletons, finish and cancel cleanly, reduced motion, dashboard section skeletons resolve per source, panel/menu motion, fast/aborted timer cleanup.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
