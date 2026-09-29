/** Run against a local shell preview. Every API call is intercepted with test fixtures. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const computer = (index, extra = {}) => ({ dn: `CN=WS-${String(index).padStart(3, '0')},CN=Computers,${rootDN}`, attributes: {
  name: `WS-${String(index).padStart(3, '0')}`, sAMAccountName: `WS-${String(index).padStart(3, '0')}$`,
  dNSHostName: `ws-${String(index).padStart(3, '0')}.example.test`, userAccountControl: index % 7 === 0 ? 4098 : 4096,
  operatingSystem: index % 2 ? 'Windows 11 Enterprise' : 'Windows Server 2022 Standard',
  lastLogonTimestamp: `${String((index % 27) + 1).padStart(2, '0')}/09/2026 08:00:00`, whenCreated: '14/08/2025 15:40:15', ...extra,
} });
const computers = Array.from({ length: 40 }, (_, index) => computer(index));
computers[3].attributes.description = '<img src=x onerror=alert(1)>';
const ownerDN = `CN=Dana Whitfield,OU=Staff,${rootDN}`;
computers[5].attributes.managedBy = ownerDN;

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = []; const listRequests = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = route.request().postDataJSON();
    if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol: 'LDAPS', username: 'tester', domain: 'example.test' } });
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN, domain: 'example.test' } });
    if (path.endsWith('/get/domaincomputer')) { listRequests.push(data); return route.fulfill({ json: computers }); }
    if (path.endsWith('/get/domainobject')) {
      const found = computers.find((item) => item.dn === data.searchbase) ?? computers[0];
      return route.fulfill({ json: [{ ...found, attributes: { objectClass: ['top', 'person', 'user', 'computer'], memberOf: [`CN=Workstations,CN=Users,${rootDN}`], ...found.attributes } }] });
    }
    return route.fulfill({ json: [] });
  });
  const rows = page.locator('#grid-body tr[data-dn]');

  await page.goto(`${base}/computers`);
  await rows.first().waitFor();
  assert.equal(await page.getByRole('heading', { name: 'Computers', level: 1 }).isVisible(), true);
  assert.equal(await page.locator('#grid-count').textContent(), '40 computers');
  assert.equal(listRequests[0].raw, true);
  assert.deepEqual([...listRequests[0].properties].sort(), ['dNSHostName', 'description', 'lastLogonTimestamp', 'name', 'operatingSystem', 'userAccountControl', 'whenCreated'].sort());
  assert.deepEqual(await page.locator('#grid-head .column-sort__label').allTextContents(), ['name', 'dNSHostName', 'Status', 'operatingSystem', 'description', 'lastLogonTimestamp', 'whenCreated']);
  assert.equal(await page.locator('#grid-body img').count(), 0);
  assert.equal(await rows.first().locator('.type--computer').count(), 1);
  await page.locator('#grid-filter').fill('ws-007');
  assert.equal(await rows.first().locator('.state').textContent(), 'Disabled');
  await page.locator('#grid-filter').fill('server 2022');
  assert.equal(await page.locator('#grid-count').textContent(), '20 of 40 computers');
  await page.locator('#grid-filter').fill('');
  await page.getByRole('button', { name: 'lastLogonTimestamp', exact: true }).click();
  assert.equal(await page.locator('th[aria-sort]').getAttribute('aria-sort'), 'ascending');

  await rows.filter({ hasText: 'WS-010' }).click();
  const panel = page.locator('#object-panel');
  await panel.locator('.property-grid').waitFor();
  assert.equal(await panel.locator('[data-panel-title] > .type--computer').count(), 1);
  assert.equal(await panel.locator('[data-panel-title] > h1 + .object-title__copy + .state').count(), 1);
  assert.deepEqual(await panel.locator('[role="tab"]:not([hidden])').evaluateAll((tabs) => tabs.map((tab) => tab.getAttribute('aria-label'))), ['Attributes', 'Member of 1', 'Security']);
  assert.equal(new URL(page.url()).searchParams.get('dn'), `CN=WS-010,CN=Computers,${rootDN}`);
  await page.keyboard.press('Escape');

  const searchMenu = page.locator('#search-menu');
  await page.getByRole('button', { name: /^Search options/ }).click();
  assert.equal(await searchMenu.getByRole('checkbox').count(), 13);
  await searchMenu.getByRole('checkbox', { name: 'Enabled computers', exact: true }).check();
  await searchMenu.getByRole('checkbox', { name: 'Disabled computers', exact: true }).check();
  assert.equal(await searchMenu.getByRole('checkbox', { name: 'Enabled computers', exact: true }).isChecked(), false);
  await searchMenu.getByRole('checkbox', { name: 'Workstations', exact: true }).check();
  await searchMenu.getByRole('checkbox', { name: 'Servers', exact: true }).check();
  assert.equal(await searchMenu.getByRole('checkbox', { name: 'Workstations', exact: true }).isChecked(), false);
  await searchMenu.getByRole('checkbox', { name: 'Exclude domain controllers', exact: true }).check();
  const beforeCancel = listRequests.length;
  await page.keyboard.press('Escape');
  assert.equal(listRequests.length, beforeCancel);
  await page.getByRole('button', { name: /^Search options/ }).click();
  assert.equal(await searchMenu.getByRole('checkbox', { name: 'Disabled computers', exact: true }).isChecked(), false);
  for (const label of ['Enabled computers', 'Servers', 'Exclude domain controllers', 'Obsolete operating systems',
    'Has a service principal name', 'Unconstrained delegation', 'Constrained delegation',
    'Resource-based constrained delegation', 'Has key credentials', 'LAPS', 'Pre-created Windows 2000 accounts']) {
    await searchMenu.getByRole('checkbox', { name: label, exact: true }).check();
  }
  await searchMenu.locator('summary').click();
  await searchMenu.getByRole('textbox', { name: 'Search base' }).fill(`OU=Servers,${rootDN}`);
  await searchMenu.getByRole('combobox', { name: 'Scope' }).selectOption('LEVEL');
  await searchMenu.getByRole('textbox', { name: 'Identity' }).fill('WS-010');
  await searchMenu.getByRole('textbox', { name: 'LDAP filter' }).fill('(operatingSystem=Windows*)');
  const searched = page.waitForResponse((response) => response.url().endsWith('/get/domaincomputer'));
  await searchMenu.getByRole('button', { name: 'Apply' }).click();
  await searched;
  const query = listRequests.at(-1);
  assert.equal(query.searchbase, `OU=Servers,${rootDN}`);
  assert.equal(query.search_scope, 'LEVEL');
  assert.deepEqual(query.args, {
    enabled: true, notworkstation: true, excludedcs: true, obsolete: true, spn: true,
    unconstrained: true, trustedtoauth: true, rbcd: true, shadowcred: true, laps: true, pre2k: true,
    identity: 'WS-010', ldapfilter: '(operatingSystem=Windows*)',
  });
  const refreshed = page.waitForResponse((response) => response.url().endsWith('/get/domaincomputer'));
  await page.locator('#grid-refresh').click(); await refreshed;
  assert.deepEqual(listRequests.at(-1).args, query.args);
  assert.equal(await page.locator('#grid-search .fields-trigger__count').textContent(), '15');

  await page.getByRole('button', { name: /^Fields/ }).click();
  await page.locator('#fields-menu').getByRole('checkbox', { name: 'operatingSystemVersion, OS version', exact: true }).check();
  await page.locator('#fields-menu').getByRole('checkbox', { name: 'managedBy, Managed by', exact: true }).check();
  await page.keyboard.press('Escape');
  await page.waitForFunction(() => [...document.querySelectorAll('#grid-head .column-sort__label')].some((node) => node.textContent === 'operatingSystemVersion'));
  assert.equal((await page.evaluate(() => JSON.parse(localStorage.getItem('powerview.computers.columns')))).includes('osVersion'), true);
  assert.equal(await page.evaluate(() => localStorage.getItem('powerview.users.columns')), null);
  assert.deepEqual(listRequests.at(-1).args, query.args);
  const managedBy = page.getByRole('button', { name: ownerDN });
  await managedBy.waitFor();
  assert.match(await managedBy.evaluate((node) => getComputedStyle(node).fontFamily), /mono|Menlo|Consolas/i);
  await managedBy.click();
  await page.waitForFunction((dn) => new URL(location.href).searchParams.get('dn') === dn, ownerDN);
  assert.equal(await page.locator('#grid-body tr[aria-selected="true"]').count(), 0);
  await page.locator('#object-panel').getByRole('button', { name: 'Close details' }).click();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${base}/computers`);
  await rows.first().waitFor();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await page.getByRole('button', { name: /^Search options/ }).click();
  await searchMenu.getByRole('checkbox', { name: 'LAPS', exact: true }).check();
  await searchMenu.getByRole('button', { name: 'Apply', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#grid-search').getAttribute('aria-label') === 'Search options, 1 active');
  await page.getByRole('button', { name: /^Search options/ }).click();
  await searchMenu.getByRole('button', { name: 'Clear', exact: true }).click();
  const cleared = page.waitForResponse((response) => response.url().endsWith('/get/domaincomputer'));
  await searchMenu.getByRole('button', { name: 'Apply', exact: true }).click(); await cleared;
  assert.equal(listRequests.at(-1).args, undefined);
  assert.deepEqual(errors, []);
  console.log('PASS: computer endpoint and default properties, columns, safe cells, status, filtering, sorting, side panel tabs, search base/scope/identity/LDAP filter, independent Fields storage, navigable monospace Managed by DN, mobile overflow, no runtime errors.');
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
