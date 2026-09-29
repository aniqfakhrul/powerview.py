const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const dn = 'CN=svc.backup,DC=example,DC=test';
const fixture = [{ attributes: ['ALLOWED', 'DENIED', 'ALLOWED'].map((effect, index) => ({
  ObjectDN: dn, ObjectSID: 'S-1-5-21-1-1003', ACEType: `ACCESS_${effect}_OBJECT_ACE`,
  SecurityIdentifier: index ? 'EXAMPLE\\alex.morgan' : '(Helpdesk operators) -> EXAMPLE\\alex.morgan',
  GrantedVia: index ? 'Direct' : 'Helpdesk operators',
  ActiveDirectoryRights: index === 1 ? ['ReadControl', 'WriteDACL'] : ['ControlAccess'],
  ObjectAceType: 'User-Force-Change-Password', ACEFlags: ['INHERITED_ACE'],
})) }];
(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    let mode = 'success';
    const calls = [], errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      if (!route.request().url().includes('get/domainobjectacl')) return route.fulfill({ json: { status: 'OK', available: false } });
      calls.push(route.request().postDataJSON());
      if (mode === 'error') return route.fulfill({ status: 400, json: { error: 'Target was not found.' } });
      if (mode === 'slow') await new Promise((resolve) => setTimeout(resolve, 300));
      await route.fulfill({ json: mode === 'empty' ? [] : fixture });
    });
    await page.goto(base + '/pathfinder');
    await page.getByText('Find ACL relations', { exact: true }).waitFor();
    assert.equal(await page.locator('#pathfinder-find').isDisabled(), true);
    assert.equal(await page.locator('#pathfinder-depth').isDisabled(), true);
    await page.locator('#pathfinder-target').press('Enter');
    assert.equal(calls.length, 0);
    assert.equal(await page.getByRole('link', { name: 'Graph', exact: true }).count(), 0);
    await page.locator('#pathfinder-target').fill('svc.backup');
    await page.locator('#pathfinder-principal').fill('alex.morgan');
    await page.locator('#pathfinder-find').click();
    await page.locator('#grid-body tr[data-key]').first().waitFor();
    assert.deepEqual(calls[0], { identity: 'svc.backup', security_identifier: 'alex.morgan', depth: 2, no_cache: false, resolveguids: true, no_vuln_check: true });
    assert.equal(await page.locator('#pathfinder-hint').textContent(), 'ACEs granted to alex.morgan (+2 group levels) on svc.backup');
    assert.equal(await page.locator('#pathfinder-depth').isDisabled(), false);
    assert.equal(await page.locator('#grid-body tr[data-key]').count(), 3);
    assert.equal(await page.locator('#grid-body .cell-name').first().getAttribute('title'), dn);
    await page.getByRole('button', { name: 'SecurityIdentifier', exact: true }).waitFor();
    await page.locator('#grid-body tr[data-key="0:1"]').click();
    assert.equal(await page.locator('#grid-body tr[aria-selected="true"]').count(), 1);
    assert.match(await page.locator('[data-panel-body]').innerText(), /WriteDACL/);
    assert.equal(await page.locator('[data-panel-body] tr').filter({ has: page.locator('th', { hasText: /^Rights$/ }) }).locator('.value').count(), 2);
    assert.match(await page.locator('[data-panel-body]').innerText(), /Granted via\s+Direct/);
    assert.match(await page.locator('#panel-explorer').getAttribute('href'), /dn=CN/);
    assert.deepEqual(Object.fromEntries(new URL(page.url()).searchParams), { target: 'svc.backup', principal: 'alex.morgan', depth: '2' });
    await page.getByRole('button', { name: 'Find all ACEs on this target', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('#grid-refresh').disabled);
    assert.deepEqual(calls.at(-1), { identity: dn, depth: 0, no_cache: false, resolveguids: true, no_vuln_check: true });
    assert.equal(await page.locator('#pathfinder-principal').inputValue(), '');
    assert.equal(await page.locator('#object-panel').isHidden(), true);
    await page.locator('#grid-filter').fill('WriteDACL');
    assert.equal(await page.locator('#grid-body tr[data-key]').count(), 1);
    assert.equal(calls.length, 2);
    const downloadEvent = page.waitForEvent('download');
    await page.locator('#pathfinder-export').click();
    const download = await downloadEvent;
    const exported = JSON.parse(await fs.readFile(await download.path(), 'utf8'));
    assert.equal(exported.aces.length, 1);
    assert.equal(exported.export_scope, 'Filtered rows');
    assert.match(download.suggestedFilename(), /^powerview-pathfinder-\d{4}-.*\.json$/);
    await page.locator('#grid-filter').fill('');
    await page.locator('#grid-refresh').click();
    await page.waitForFunction(() => !document.querySelector('#grid-refresh').disabled);
    assert.equal(calls.at(-1).no_cache, true);
    {
      if (process.env.PATHFINDER_SCREENSHOT_DIR) await fs.mkdir(process.env.PATHFINDER_SCREENSHOT_DIR, { recursive: true });
      for (const [name, viewport, theme] of [
        ['desktop-light', { width: 1440, height: 1000 }, 'light'],
        ['desktop-dark', { width: 1440, height: 1000 }, 'dark'],
        ['mobile-light', { width: 390, height: 844 }, 'light'],
      ]) {
        await page.setViewportSize(viewport);
        await page.emulateMedia({ colorScheme: theme });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        if (process.env.PATHFINDER_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.PATHFINDER_SCREENSHOT_DIR}/${name}.png`, fullPage: true, animations: 'disabled' });
      }
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.locator('#pathfinder-target').fill('');
    await page.locator('#pathfinder-principal').fill('alex.morgan');
    await page.locator('#pathfinder-find').click();
    await page.waitForFunction(() => !document.querySelector('#grid-refresh').disabled);
    assert.equal('identity' in calls.at(-1), false);
    assert.equal(calls.at(-1).security_identifier, 'alex.morgan');
    mode = 'empty';
    await page.locator('#grid-refresh').click();
    await page.getByText('No matching ACEs returned', { exact: true }).waitFor();
    mode = 'error';
    await page.locator('#pathfinder-find').click();
    await page.getByText('Target was not found.', { exact: true }).first().waitFor();
    assert.equal(await page.locator('#pathfinder-export').isDisabled(), true);
    mode = 'slow';
    await page.locator('#pathfinder-find').click();
    await page.locator('#pathfinder-cancel').click();
    await page.getByText('Search cancelled', { exact: true }).waitFor();
    await page.waitForTimeout(500);
    assert.equal(await page.getByText('Search cancelled', { exact: true }).isVisible(), true);
    assert.equal(await page.locator('#grid-body tr[data-key]').count(), 0);
    assert.equal(await page.locator('#pathfinder-export').isDisabled(), true);
    assert.deepEqual(errors, []);
    console.log('Pathfinder browser checks passed.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
