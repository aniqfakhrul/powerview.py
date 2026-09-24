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
const groupDN = `CN=VPN Users,CN=Users,${rootDN}`;
let users = Array.from({ length: 450 }, (_, index) => user(index));

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const securityRequests = [];
  const errors = []; const writes = []; const userRequests = []; let createResponse = false; let failUsers = false;
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = route.request().postDataJSON();
    if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol: 'LDAPS', username: 'tester', domain: 'example.test' } });
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN, domain: 'example.test' } });
    if (path.endsWith('/get/domainobjectowner')) {
      securityRequests.push({ path, data });
      return route.fulfill({ json: [{ dn: data.identity, attributes: { Owner: 'EXAMPLE\\Domain Admins (S-1-5-21-1-2-3-512)' } }] });
    }
    if (path.endsWith('/get/domainobjectacl')) {
      securityRequests.push({ path, data });
      if (data.identity === groupDN) return route.fulfill({ json: null });
      return route.fulfill({ json: [{ attributes: [
        { ACEType: 'ACCESS_ALLOWED_OBJECT_ACE', ACEFlags: 'CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE', SecurityIdentifier: 'EXAMPLE\\Helpdesk', AccessMask: 'WriteProperty', ObjectAceType: 'Telephone-Number', InheritanceType: 'User' },
        { ACEType: 'ACCESS_ALLOWED_ACE', ACEFlags: 'None', SecurityIdentifier: 'EXAMPLE\\Helpdesk', AccessMask: 'ReadProperty, WriteProperty', ObjectAceType: null },
        { ACEType: 'ACCESS_DENIED_OBJECT_ACE', ACEFlags: 'None', SecurityIdentifier: 'Everyone', AccessMask: 'ExtendedRight', ObjectAceType: 'User-Change-Password' },
        { ACEType: 'ACCESS_ALLOWED_ACE', ACEFlags: 'CONTAINER_INHERIT_ACE, INHERITED_ACE', SecurityIdentifier: 'EXAMPLE\\Domain Admins', AccessMask: 'FullControl', ObjectAceType: null },
      ] }] });
    }
    if (path.endsWith('/get/domainobject') && data.searchbase === groupDN) {
      return route.fulfill({ json: [{ dn: groupDN, attributes: { name: 'VPN Users', objectClass: ['top', 'group'], groupType: -2147483646,
        'member;range=0-2': [`CN=User 002,CN=Users,${rootDN}`, `CN=User 001,CN=Users,${rootDN}`, `CN=User 003,CN=Users,${rootDN}`] } }] });
    }
    if (path.endsWith('/get/domainobject')) {
      const found = users.find((item) => item.dn === data.searchbase) ?? users[0];
      return route.fulfill({ json: [{ ...found, attributes: { objectClass: ['top', 'person', 'user'], memberOf: [groupDN, `CN=Staff,CN=Users,${rootDN}`], ...found.attributes } }] });
    }
    if (path.endsWith('/get/domainuser')) {
      userRequests.push(data);
      return failUsers ? route.fulfill({ status: 400, json: { error: 'Search failed (test)' } }) : route.fulfill({ json: users });
    }
    writes.push({ path, data });
    if (path.endsWith('/set/domainobject') && data._set) {
      users = users.map((item) => item.dn === data.identity ? { ...item, attributes: { ...item.attributes, [data._set.attribute]: data._set.value[0] } } : item);
      return route.fulfill({ json: true });
    }
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

  await page.locator('#grid-filter').fill('user12');
  assert.equal(await rows.count(), 11);
  await rows.filter({ hasText: 'User 012' }).click();
  const editPanel = page.locator('#object-panel');
  await editPanel.getByRole('button', { name: 'Edit sAMAccountName' }).click();
  await editPanel.getByRole('textbox', { name: 'Value 1' }).fill('changed.account');
  await editPanel.getByRole('button', { name: 'Save', exact: true }).click();
  await page.waitForFunction(() => document.querySelectorAll('#grid-body tr[data-dn]').length === 10);
  assert.equal(await page.locator('#grid-count').textContent(), '10 of 450 users');
  assert.equal(await editPanel.isVisible(), true);
  assert.equal(await editPanel.locator('[data-panel-title] h1').textContent(), 'User 012');
  await rows.first().click();
  await page.setViewportSize({ width: 900, height: 900 });
  await page.waitForFunction(() => document.querySelector('#object-panel').contains(document.activeElement));
  await page.keyboard.press('Escape');
  assert.equal(await editPanel.isVisible(), false);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator('#grid-filter').fill('user 012');
  assert.equal(await rows.count(), 1);
  assert.equal(await page.locator('#grid-count').textContent(), '1 of 450 users');
  await page.locator('#grid-filter').fill('nobody');
  await page.getByRole('heading', { name: 'No users match' }).waitFor();
  await page.locator('#grid-filter').fill('');

  const dialog = page.locator('#user-dialog');
  const writesBeforeCreate = writes.length;
  await page.getByRole('button', { name: 'New user', exact: true }).click();
  assert.equal(await dialog.getByRole('textbox', { name: 'Container' }).inputValue(), `CN=Users,${rootDN}`);
  await dialog.getByRole('textbox', { name: 'Name' }).fill('Bad,Name');
  await dialog.getByLabel('Password').fill('Secret123!');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await page.waitForFunction(() => !document.querySelector('#user-error').hidden);
  assert.equal(writes.length, writesBeforeCreate);
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
  assert.equal(await panel.getByRole('tab', { name: 'Attributes' }).getAttribute('aria-selected'), 'true');
  assert.deepEqual(await panel.locator('[role="tab"]:not([hidden])').evaluateAll((tabs) => tabs.map((tab) => tab.getAttribute('aria-label'))), ['Attributes', 'Member of 2', 'Security']);
  assert.equal(await panel.getByRole('tab', { name: 'Overview' }).count(), 0);
  assert.equal(await panel.locator('[data-panel-title] .object-title__type').textContent(), 'User');
  assert.equal(await panel.locator('[data-panel-title] .state').textContent(), 'Enabled');
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await panel.getByRole('button', { name: 'Copy distinguished name' }).click();
  await page.waitForFunction(() => document.querySelector('#status-message').textContent === 'Distinguished name copied');
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), `CN=Second Person,CN=Users,${rootDN}`);
  assert.equal(await panel.getByRole('searchbox', { name: 'Filter attributes' }).isVisible(), true);
  assert.equal(securityRequests.length, 0);
  await panel.getByRole('tab', { name: 'Security' }).click();
  await panel.locator('.security__row').first().waitFor();
  assert.deepEqual(securityRequests.map((item) => [item.path, item.data.identity, item.data.search_scope]), [
    ['/api/get/domainobjectowner', `CN=Second Person,CN=Users,${rootDN}`, 'BASE'],
    ['/api/get/domainobjectacl', `CN=Second Person,CN=Users,${rootDN}`, 'BASE'],
  ]);
  assert.equal(await panel.locator('.security__owner p').textContent(), 'EXAMPLE\\Domain Admins');
  assert.equal(await panel.locator('.security__owner code').textContent(), 'S-1-5-21-1-2-3-512');
  const aceRows = panel.locator('.security__row');
  assert.deepEqual(await panel.locator('.security__row td:first-child').allTextContents(), ['Deny', 'Allow', 'Allow', 'Allow']);
  assert.equal(await aceRows.nth(0).locator('td').nth(3).textContent(), 'User-Change-Password');
  const scoped = aceRows.filter({ hasText: 'Telephone-Number' });
  assert.equal(await scoped.locator('td').nth(4).textContent(), 'Descendants only · User objects');
  await scoped.click();
  assert.equal(await scoped.getAttribute('aria-expanded'), 'true');
  const detail = scoped.locator('xpath=following-sibling::tr[1]');
  assert.equal(await detail.isVisible(), true);
  assert.match(await detail.textContent(), /FlagsCONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE/);
  await panel.getByLabel('Hide inherited').check();
  assert.equal(await aceRows.count(), 3);
  await panel.getByRole('tab', { name: 'Attributes' }).click();
  await panel.getByRole('tab', { name: 'Security' }).click();
  assert.equal(securityRequests.length, 2);
  await panel.getByRole('tab', { name: 'Attributes' }).click();
  assert.equal(await panel.getByRole('tab', { name: /^Members/ }).isVisible(), false);
  await panel.getByRole('tab', { name: 'Member of 2' }).click();
  assert.equal(await panel.locator('.membership:not([hidden]) .membership__item').count(), 2);
  await panel.getByRole('searchbox', { name: 'Filter groups' }).fill('vpn');
  assert.equal(await panel.locator('.membership:not([hidden]) .membership__item').count(), 1);
  await panel.locator('.membership:not([hidden]) .membership__item').first().click();
  await panel.getByRole('tab', { name: 'Members 3' }).waitFor();
  await panel.getByRole('tab', { name: 'Security' }).click();
  await panel.getByRole('heading', { name: 'Cannot read security' }).waitFor();
  assert.equal(await panel.locator('.security__row').count(), 0);
  assert.equal(await panel.locator('[data-panel-title] h1').textContent(), 'VPN Users');
  assert.equal(await panel.getByRole('tab', { name: 'Member of 2' }).isVisible(), false);
  await panel.getByRole('tab', { name: 'Members 3' }).click();
  assert.deepEqual(await panel.locator('.membership:not([hidden]) .membership__name').allTextContents(), ['User 001', 'User 002', 'User 003']);
  assert.equal(await panel.locator('.membership:not([hidden]) .membership__note').isVisible(), true);
  await page.locator('#grid-body tr[data-dn]').first().click();
  await panel.getByRole('tab', { name: 'Member of 2' }).waitFor();
  assert.equal(await panel.getByRole('tab', { name: 'Attributes' }).getAttribute('aria-selected'), 'true');
  await panel.getByRole('tab', { name: 'Attributes' }).focus();
  await page.keyboard.press('End');
  assert.equal(await panel.getByRole('tab', { name: 'Security' }).getAttribute('aria-selected'), 'true');
  await page.keyboard.press('Home');
  assert.equal(await panel.getByRole('tab', { name: 'Attributes' }).getAttribute('aria-selected'), 'true');
  await panel.locator('.property-grid').waitFor();
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  assert.equal(new URL(page.url()).searchParams.get('dn'), `CN=Second Person,CN=Users,${rootDN}`);
  assert.equal(new URL(await panel.getByRole('link', { name: 'Open in Explorer' }).getAttribute('href'), base).searchParams.get('dn'), `CN=Second Person,CN=Users,${rootDN}`);
  await panel.getByRole('button', { name: 'Edit sAMAccountName' }).click();
  await panel.getByRole('textbox', { name: 'Value 1' }).fill('updated.account');
  const before = page.url();
  await panel.getByRole('link', { name: 'Open in Explorer' }).click();
  await page.waitForTimeout(300);
  assert.equal(page.url(), before);
  assert.equal(await panel.getByRole('textbox', { name: 'Value 1' }).inputValue(), 'updated.account');
  await panel.getByRole('button', { name: 'Save', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#grid-body tr[aria-selected="true"]')?.textContent.includes('updated.account'));
  assert.equal(await rows.first().getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('#grid-filter').inputValue(), 'Second Person');
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
  const focusedDN = await rows.nth(2).getAttribute('data-dn');
  await rows.nth(2).focus();
  await page.keyboard.press('Enter');
  await panel.locator('.property-grid').waitFor();
  assert.equal(await panel.evaluate((node) => node.contains(document.activeElement)), true);
  assert.equal(await page.locator('.grid-main').evaluate((node) => node.inert), true);
  await page.keyboard.press('Escape');
  assert.equal(await panel.isVisible(), false);
  assert.equal(await page.locator('.grid-main').evaluate((node) => node.inert), false);
  assert.equal(await page.evaluate(() => document.activeElement.dataset.dn), focusedDN);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  assert.deepEqual(errors, []);
  console.log('PASS: End/Home across unrendered rows, sorting disabled while errored, raw user request, flag-name status, chronological day-first date sorting, sort focus retention, failed post-create refresh stays visible, incremental rendering, safe cells, sorting, filtering, empty filter state, new user validation and failed-create preservation, create refresh, side panel (save re-applies filter, breakpoint focus transfer, Open in Explorer draft guard, grid row reconciled after save, mobile overlay focus/inert/Escape/restore, unavailable ACL error, inheritance scope and expandable ACE details, lazy Security tab with owner, deny-first ACL, inherited toggle, per-object caching, Members/Member of tabs by type, counts, filter, partial-range note, membership navigation, header type/status/copy-DN, Attributes-first tab order, tab keyboard switching, open, URL state, Explorer link, Escape layering, deep link, close), mobile overflow, no runtime errors.');
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
