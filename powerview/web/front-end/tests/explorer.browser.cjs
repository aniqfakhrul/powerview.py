/** Run against a local shell preview. Every API call is intercepted with test fixtures. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const peopleDN = `OU=People,${rootDN}`;
const row = (name, type = 'user', parent = peopleDN) => ({ dn: `CN=${name},${parent}`, attributes: {
  name, objectClass: type === 'computer' ? ['top', 'user', 'computer'] : ['top', type],
  description: 'Browser fixture', whenChanged: '20260924120000.0Z', manager: `CN=Person 002,${peopleDN}`,
} });
const objects = Array.from({ length: 605 }, (_, index) => row(`Person ${String(index).padStart(3, '0')}`));
objects[0].attributes.description = '<img src=x onerror=alert(1)>';
objects[1] = row('Person 001', 'computer');
const container = { dn: peopleDN, attributes: { name: 'People', objectClass: ['organizationalUnit'] } };
const contextRecord = { dn: rootDN, attributes: { name: 'example', objectClass: ['domainDNS'] } };
const connection = { domain: 'example.test', ldap_address: '10.0.0.10', nameserver: '10.0.0.10', protocol: 'LDAPS', status: 'OK', username: 'tester' };

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
  const errors = []; const writes = []; let mutationResponse = false; let failReads = false;
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/**', async (route) => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    const data = request.postDataJSON();
    let response;
    if (path.endsWith('/connectioninfo')) response = connection;
    else if (path.endsWith('/get/domaininfo')) response = { root_dn: rootDN, domain: 'example.test' };
    else if (path.endsWith('/server/info')) response = { raw: { namingContexts: [rootDN] } };
    else if (path.endsWith('/get/domainobject')) {
      if (failReads) return route.fulfill({ status: 400, json: { error: 'Read denied (test)' } });
      assert.deepEqual(data.properties, data.search_scope === 'BASE' ? ['*'] : ['name', 'objectClass']);
      if (data.search_scope === 'BASE') response = [objects.find((item) => item.dn === data.searchbase) || (data.searchbase === peopleDN ? container : contextRecord)];
      else response = data.searchbase === rootDN ? [container] : data.searchbase === peopleDN ? objects : [];
    } else { writes.push({ path, data }); response = mutationResponse; }
    await route.fulfill({ json: response });
  });
  const heading = (name) => page.locator('#object-title').getByRole('heading', { name, exact: true });
  const select = async (name) => {
    await page.getByRole('treeitem', { name, exact: true }).locator(':scope > .tree-line').click();
    await heading(name).waitFor();
    await page.locator('#properties[aria-busy="false"]').waitFor();
  };
  const dialog = page.locator('#object-dialog');
  const visibleChildren = page.locator('[aria-label="People"] > .tree-group > .tree-item:not([hidden])');

  await page.goto(base);
  await heading('example').waitFor();
  const indicator = page.locator('#connection-status');
  await page.locator('#connection-status[data-state="ok"]').waitFor();
  assert.match(await indicator.textContent(), /LDAPS\s+tester@example\.test\s+10\.0\.0\.10/);
  assert.match(await indicator.getAttribute('title'), /Name server: 10\.0\.0\.10/);
  assert.equal(await page.locator('#address').inputValue(), rootDN);
  await select('People');
  await page.waitForFunction(() => document.querySelectorAll('[aria-label="People"] > .tree-group > .tree-item').length === 500);
  await page.getByRole('button', { name: 'Show 105', exact: true }).click();
  assert.equal(await visibleChildren.count(), 605);
  await page.locator('#tree-filter').fill('Person 604');
  assert.equal(await visibleChildren.count(), 1);
  await page.locator('#tree-filter').fill('');
  await select('Person 001');
  assert.equal(await page.locator('.object-title__type').textContent({ timeout: 5000 }), 'Computer');
  await select('Person 000');
  assert.equal(await page.locator('#properties img').count(), 0);
  assert.equal(await page.getByText('Read only').count(), 0);

  await page.getByRole('button', { name: 'Edit description', exact: true }).click();
  await page.getByRole('textbox', { name: 'Value 1', exact: true }).fill('a,b=c');
  await page.getByRole('button', { name: 'Add value', exact: true }).click();
  await page.getByRole('textbox', { name: 'Value 2', exact: true }).fill('second');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('.value-editor .form-error')?.textContent.includes('did not confirm'));
  assert.deepEqual(writes.at(-1).data._set, { attribute: 'description', value: ['a,b=c', 'second'] });
  await page.getByRole('treeitem', { name: 'Person 001', exact: true }).locator(':scope > .tree-line').click();
  assert.equal(await heading('Person 000').isVisible(), true);
  mutationResponse = true;
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await page.waitForFunction(() => !document.querySelector('.value-editor') && document.querySelectorAll('.property-grid tbody tr').length > 0);

  await page.getByRole('button', { name: 'New', exact: true }).click();
  await dialog.getByRole('combobox', { name: 'Type' }).selectOption('ou');
  await dialog.getByRole('textbox', { name: 'Name', exact: true }).fill('Test OU');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await page.waitForFunction(() => !document.querySelector('#object-dialog').open);
  assert.equal(writes.at(-1).data.args.protectedfromaccidentaldeletion, false);
  assert.equal(writes.at(-1).data.basedn, peopleDN);

  await select('Person 000');
  await page.locator('.value--dn', { hasText: `CN=Person 002,${peopleDN}` }).first().click();
  await heading('Person 002').waitFor();
  assert.equal(await page.locator('.tree-item[aria-selected="true"]').getAttribute('aria-label'), 'Person 002');

  await select('Person 000');
  await page.getByRole('button', { name: 'Move', exact: true }).click();
  await dialog.getByRole('textbox', { name: 'Destination container', exact: true }).fill(rootDN);
  await dialog.getByRole('button', { name: 'Move', exact: true }).click();
  await page.waitForFunction(() => !document.querySelector('#object-dialog').open);
  assert.equal(writes.at(-1).data.destination_dn, rootDN);

  await select('Person 003');
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
  await page.waitForFunction(() => !document.querySelector('#object-dialog').open);
  assert.equal(writes.at(-1).path, '/api/remove/domainobject');

  failReads = true;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await page.getByRole('heading', { name: 'Cannot load this object' }).waitFor();
  failReads = false;
  await page.locator('#properties').getByRole('button', { name: 'Retry' }).click();
  await page.locator('.property-grid').waitFor();

  connection.status = 'KO';
  await page.waitForFunction(() => {
    dispatchEvent(new Event('powerview:request-failed'));
    return document.querySelector('#connection-status').dataset.state === 'down';
  }, null, { polling: 500, timeout: 10000 });
  assert.equal(await page.locator('.connection__announcer').textContent(), 'Directory connection lost');
  connection.status = 'OK';

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Directory', exact: true }).click();
  assert.equal(await page.locator('#directory-pane').isVisible(), true);
  assert.equal(await page.locator('#object-pane').evaluate((node) => node.inert), true);
  for (let index = 0; index < 12; index += 1) await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.querySelector('#directory-pane').contains(document.activeElement)), true);
  await page.getByRole('button', { name: 'Close directory', exact: true }).click();
  assert.equal(await page.locator('#directory-pane').isVisible(), false);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  assert.deepEqual(errors, []);
  console.log('PASS: connection status (live, tooltip, loss announcement), tree paging and filtering, safe rendering, multi-value editing with failed-write preservation, DN links, create/move/delete, read recovery, mobile focus containment, no runtime errors.');
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
