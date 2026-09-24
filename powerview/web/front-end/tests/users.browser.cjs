/** Run against a local shell preview. Every API call is intercepted with test fixtures. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const user = (index, extra = {}) => ({ dn: `CN=User ${String(index).padStart(3, '0')},CN=Users,${rootDN}`, attributes: {
  name: `User ${String(index).padStart(3, '0')}`, sAMAccountName: `user${index}`,
  userAccountControl: index % 5 === 0 ? ['ACCOUNTDISABLE', 'NORMAL_ACCOUNT'] : ['NORMAL_ACCOUNT'],
  description: index === 7 ? '<img src=x onerror=alert(1)>' : 'Fixture',
  whenCreated: index === 3 ? '24/09/2026 12:18:10' : index === 4 ? '05/09/2026 00:00:00' : `${String((index % 27) + 1).padStart(2, '0')}/08/2025 15:40:15`, ...extra,
} });
let users = Array.from({ length: 450 }, (_, index) => user(index));

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = []; const writes = []; const userRequests = []; let createResponse = false; let failUsers = false;
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = route.request().postDataJSON();
    if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol: 'LDAPS', username: 'tester', domain: 'example.test' } });
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN, domain: 'example.test' } });
    if (path.endsWith('/get/domainobject')) return route.fulfill({ json: [users.find((item) => item.dn === data.searchbase) ?? users[0]] });
    if (path.endsWith('/get/domainuser')) {
      userRequests.push(data);
      return failUsers ? route.fulfill({ status: 400, json: { error: 'Search failed (test)' } }) : route.fulfill({ json: users });
    }
    writes.push({ path, data });
    if (createResponse && path.endsWith("/add/domainuser")) users = [...users, { dn: `CN=${data.username},CN=Users,${rootDN}`, attributes: { name: data.username, sAMAccountName: data.username.toLowerCase(), userAccountControl: 512 } }];
    return route.fulfill({ json: createResponse });
  });
  const rows = page.locator('#grid-body tr[data-dn]');

  await page.goto(`${base}/users`);
  await rows.first().waitFor();
  assert.equal(await rows.count(), 200);
  assert.equal(await page.locator('#grid-count').textContent(), '450 users');
  await page.locator('#grid-scroll').evaluate((node) => { node.scrollTop = node.scrollHeight; });
  await page.waitForFunction(() => document.querySelectorAll('#grid-body tr[data-dn]').length > 200);
  assert.equal(await page.locator('#grid-body img').count(), 0);
  assert.equal(userRequests[0].raw, true);
  await rows.first().focus();
  await page.keyboard.press('End');
  assert.equal(await page.evaluate(() => document.activeElement.dataset.dn), `CN=User 449,CN=Users,${rootDN}`);
  await page.keyboard.press('Home');
  assert.equal(await page.evaluate(() => document.activeElement.dataset.dn), `CN=User 000,CN=Users,${rootDN}`);

  await page.locator('#grid-filter').fill('user 005');
  assert.equal(await rows.first().locator('.state').textContent(), 'Disabled');
  await page.locator('#grid-filter').fill('');

  const created = page.getByRole('button', { name: 'Created', exact: true });
  await created.focus();
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Created');
  assert.deepEqual(await rows.evaluateAll((items) => items.slice(0, 2).map((item) => item.dataset.dn)),
    [`CN=User 003,CN=Users,${rootDN}`, `CN=User 004,CN=Users,${rootDN}`]);

  await page.getByRole('button', { name: 'Name', exact: true }).click();
  await page.getByRole('button', { name: 'Name', exact: true }).click();
  assert.equal(await page.locator('th[aria-sort]').getAttribute('aria-sort'), 'descending');
  assert.equal(await rows.first().getAttribute('data-dn'), `CN=User 449,CN=Users,${rootDN}`);
  await page.getByRole('button', { name: 'Status', exact: true }).click();
  assert.equal(await rows.first().locator('.state').textContent(), 'Enabled');

  await page.locator('#grid-filter').fill('user 012');
  assert.equal(await rows.count(), 1);
  assert.equal(await page.locator('#grid-count').textContent(), '1 of 450 users');
  await page.locator('#grid-filter').fill('nobody');
  await page.getByRole('heading', { name: 'No users match' }).waitFor();
  await page.locator('#grid-filter').fill('');

  const dialog = page.locator('#user-dialog');
  await page.getByRole('button', { name: 'New user', exact: true }).click();
  assert.equal(await dialog.getByRole('textbox', { name: 'Container' }).inputValue(), `CN=Users,${rootDN}`);
  await dialog.getByRole('textbox', { name: 'Name' }).fill('Bad,Name');
  await dialog.getByLabel('Password').fill('Secret123!');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await page.waitForFunction(() => !document.querySelector('#user-error').hidden);
  assert.equal(writes.length, 0);
  await dialog.getByRole('textbox', { name: 'Name' }).fill('New Person');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#user-error').textContent.includes('did not confirm'));
  assert.deepEqual(writes.at(-1), { path: '/api/add/domainuser', data: { username: 'New Person', password: 'Secret123!', basedn: `CN=Users,${rootDN}` } });
  createResponse = true;
  failUsers = true;
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await page.getByRole('heading', { name: 'Cannot load users' }).waitFor();
  assert.equal(await page.getByRole('heading', { name: 'No users match' }).count(), 0);
  assert.equal(await page.locator('#grid-filter').inputValue(), '');
  assert.equal(await page.getByRole('button', { name: 'Name', exact: true }).isDisabled(), true);
  await page.getByRole('heading', { name: 'Cannot load users' }).isVisible();
  failUsers = false;
  await page.locator('#grid-message').getByRole('button', { name: 'Retry' }).click();
  await rows.first().waitFor();
  await page.getByRole('button', { name: 'New user', exact: true }).click();
  await dialog.getByRole('textbox', { name: 'Name' }).fill('Second Person');
  await dialog.getByLabel('Password').fill('Secret123!');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await page.waitForFunction(() => !document.querySelector('#user-dialog').open);
  await page.waitForFunction(() => document.querySelectorAll('#grid-body tr[data-dn]').length === 1);
  assert.equal(await page.locator('#grid-filter').inputValue(), 'Second Person');
  assert.equal(await page.locator('#status-message').textContent(), 'Created Second Person');

  await rows.first().click();
  const panel = page.locator('#object-panel');
  await panel.locator('[data-panel-title]').getByRole('heading', { name: 'Second Person' }).waitFor();
  await panel.locator('.property-grid').waitFor();
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  assert.equal(new URL(page.url()).searchParams.get('dn'), `CN=Second Person,CN=Users,${rootDN}`);
  assert.equal(new URL(await panel.getByRole('link', { name: 'Open in Explorer' }).getAttribute('href'), base).searchParams.get('dn'), `CN=Second Person,CN=Users,${rootDN}`);
  await panel.getByRole('searchbox', { name: 'Filter attributes' }).fill('name');
  await page.keyboard.press('Escape');
  assert.equal(await panel.isVisible(), true);
  await page.keyboard.press('Escape');
  assert.equal(await panel.isVisible(), false);
  assert.equal(new URL(page.url()).searchParams.get('dn'), null);

  await page.goto(`${base}/users?dn=${encodeURIComponent(`CN=User 010,CN=Users,${rootDN}`)}`);
  await panel.locator('[data-panel-title]').getByRole('heading', { name: 'User 010' }).waitFor();
  assert.equal(await page.locator('#grid-body tr[aria-selected="true"]').getAttribute('data-dn'), `CN=User 010,CN=Users,${rootDN}`);
  await panel.getByRole('button', { name: 'Close details' }).click();
  assert.equal(await panel.isVisible(), false);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${base}/users`);
  await rows.first().waitFor();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  assert.deepEqual(errors, []);
  console.log('PASS: End/Home across unrendered rows, sorting disabled while errored, raw user request, flag-name status, chronological day-first date sorting, sort focus retention, failed post-create refresh stays visible, incremental rendering, safe cells, sorting, filtering, empty filter state, new user validation and failed-create preservation, create refresh, side panel (open, URL state, Explorer link, Escape layering, deep link, close), mobile overflow, no runtime errors.');
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
