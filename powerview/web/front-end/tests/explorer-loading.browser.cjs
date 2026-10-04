/** Run against a local shell preview. Every API call is intercepted with test fixtures. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const peopleDN = `OU=People,${rootDN}`;
const container = { dn: peopleDN, attributes: { name: 'People', objectClass: ['organizationalUnit'] } };
const person = { dn: `CN=Alice,${peopleDN}`, attributes: { name: 'Alice', objectClass: ['top', 'user'] } };
const contextRecord = { dn: rootDN, attributes: { name: 'example', objectClass: ['domainDNS'] } };

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
  const errors = [];
  const gates = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = route.request().postDataJSON();
    if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
    if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [rootDN] } } });
    if (path.endsWith('/get/domainobject') && data.search_scope === 'BASE') {
      return route.fulfill({ json: [data.searchbase === peopleDN ? container : contextRecord] });
    }
    if (path.endsWith('/get/domainobject') && data.searchbase === peopleDN) {
      await new Promise((resolve) => gates.push(resolve));
      return route.fulfill({ json: [person] }).catch(() => {});
    }
    if (path.endsWith('/get/domainobject')) return route.fulfill({ json: data.searchbase === rootDN ? [container] : [] });
    return route.fulfill({ json: [] });
  });

  const people = page.getByRole('treeitem', { name: 'People', exact: true });
  const twisty = people.locator(':scope > .tree-line .tree-twisty');
  const loadingNote = people.locator(':scope > .tree-group > .tree-note', { hasText: /^Loading…$/ });
  const slowNote = people.locator(':scope > .tree-group > .tree-note', { hasText: 'Still loading…' });
  const pulse = () => twisty.locator('.icon').evaluate((icon) => getComputedStyle(icon).animationName);

  try {
    await page.goto(`${base}/explorer`);
    await people.waitFor();

    await twisty.click();
    assert.equal(await people.getAttribute('aria-busy'), 'true');
    assert.equal(await people.getAttribute('aria-expanded'), 'true');
    assert.equal(await loadingNote.count(), 0, 'no loading row before the delay');
    assert.equal(await pulse(), 'none', 'no pulse before the delay');
    await loadingNote.waitFor();
    assert.equal(await pulse(), 'tree-pulse');
    assert.equal(await loadingNote.getByRole('button').count(), 0, 'Cancel waits for a slow load');
    await slowNote.waitFor({ timeout: 5000 });
    await slowNote.getByRole('button', { name: 'Cancel', exact: true }).click();
    assert.equal(await people.getAttribute('aria-expanded'), 'false');
    assert.equal(await people.locator(':scope > .tree-group').count(), 0);
    assert.equal(await people.evaluate((node) => node === document.activeElement), true, 'focus returns to the node');
    assert.equal(await people.getAttribute('aria-busy'), 'false');
    gates.shift()();
    await page.waitForTimeout(100);
    assert.equal(await people.locator(':scope > .tree-group').count(), 0, 'a cancelled load never renders');
    assert.equal(await people.locator('.tree-note--error').count(), 0, 'cancelling is not an error');

    await twisty.click();
    await loadingNote.waitFor();
    await page.keyboard.press('ArrowLeft');
    assert.equal(await people.getAttribute('aria-expanded'), 'false', 'collapsing cancels the load');
    gates.shift()();

    await twisty.click();
    while (!gates.length) await page.waitForTimeout(10);
    gates.shift()();
    await page.getByRole('treeitem', { name: 'Alice', exact: true }).waitFor();
    assert.equal(await loadingNote.count(), 0, 'a fast load never shows the loading row');
    assert.equal(await people.getAttribute('aria-busy'), 'false');
    assert.deepEqual(errors, []);
    console.log('PASS: tree loads stay quiet for 200ms, then show a Loading row and pulse; Cancel after 3s and collapsing abort the read, restore focus, and never render or report an error; fast loads skip the row.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
