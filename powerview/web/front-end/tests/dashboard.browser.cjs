const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const collected = '2026-09-27T10:15:00+00:00';
const metadata = { domain: 'example.test', root_dn: rootDN, dc: 'dc01.example.test', collected_at: collected, read_at: collected, cached: false, sample_limit: 100 };
const names = ['svc.backup', 'svc.sql', 'svc.deploy', 'svc.reports', 'svc.legacy', 'svc.web'];
const day = (offset) => new Date(Date.UTC(2026, 8, 27) - offset * 86400000).toISOString().replace('.000Z', '+00:00');
const enabled = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))';
const object = (index) => ({ name: names[index] ?? `service.${String(index).padStart(3, '0')}`, dn: `CN=Service ${index},OU=Service Accounts,${rootDN}`, password_set: index ? day(1500 - index) : 'never', last_logon: index === 2 ? null : day(400 - index) });
const userKeys = ['preauth', 'spn', 'password_not_required', 'never_expires', 'admin', 'stale'];
const userCounts = [125, 34, 3, 82, 16, 41];
const users = Object.fromEntries(userKeys.map((key, index) => [`users_${key}`, {
  count: userCounts[index], order: key === 'stale' ? 'last_logon' : 'password_set', ldap_filter: `(&${enabled}(${key}=fixture))`,
  objects: Array.from({ length: Math.min(userCounts[index], 100) }, (_, item) => ({ ...object(item), ...(key === 'spn' ? { evidence: 'MSSQLSvc/sql.example.test:1433' } : {}) })),
}]));
const computers = Object.fromEntries(['unconstrained', 'constrained', 'password_not_required', 'stale'].map((key, index) => [`computers_${key}`, {
  count: [3, 8, 1, 27][index], order: ['name', 'name', 'password_set', 'last_logon'][index], ldap_filter: `(&${enabled}(${key}=fixture))`,
  objects: [{ name: 'APP01$', dn: `CN=APP01,OU=Servers,${rootDN}`, password_set: day(45), last_logon: day(120), os: 'Windows Server 2022', ...(key === 'constrained' ? { evidence: 'HTTP/backend.example.test' } : {}) }],
}]));
users.users_preauth.objects[1].name = '<img src=x onerror=alert(1)>';
users.users_preauth.objects[1].dn = `CN=Last\\, First,OU=Service Accounts,${rootDN}`;
const privilegedAccount = (name, extra) => ({ name, dn: `CN=${name},OU=Admins,${rootDN}`, groups: ['Domain Admins'], enabled: true, protected: false, stale: false, old_password: false, never_expires: false, last_logon: '2026-09-20T08:00:00+00:00', password_set: '2026-06-01T08:00:00+00:00', ...extra });
const fixtures = {
  privileged: { ...metadata, inactive_days: 90, password_age_days: 365, protected_users: true,
    counts: { accounts: 3, enabled: 2, unprotected: 1, stale: 1, old_password: 1, never_expires: 0 },
    groups: [{ name: 'Administrators', dn: `CN=Administrators,CN=Builtin,${rootDN}`, count: 2 }, { name: 'Domain Admins', dn: `CN=Domain Admins,CN=Users,${rootDN}`, count: 2 }],
    accounts: [
      privilegedAccount('alice.admin', { groups: ['Administrators', 'Domain Admins'], protected: true }),
      privilegedAccount('bob.admin', { stale: true, old_password: true, last_logon: null }),
      privilegedAccount('old.admin', { enabled: false }),
    ] },
  domain: { ...metadata, policy: { minPwdLength: 12, pwdHistoryLength: 24, maxPwdAge: 3628800, minPwdAge: 86400, lockoutThreshold: 5, lockoutDuration: 1800, pwdProperties: 1, 'ms-DS-MachineAccountQuota': 10 } },
  inventory: { ...metadata, ca_error: null, counts: { groups: 248, ous: 32, gpos: 47, trusts: 2, cas: 2, published_templates: 12 }, trusts: [
    { name: 'partners.test', partner: 'partners.test', dn: `CN=partners.test,CN=System,${rootDN}`, direction: 2, attributes: 8 },
    { name: 'child.example.test', partner: 'child.example.test', dn: `CN=child.example.test,CN=System,${rootDN}`, direction: 3, attributes: 32 },
  ] },
  users: { ...metadata, counts: { total: 1428, enabled: 1214, disabled: 208, unknown: 6, missing_logon: 28 }, findings: users },
  computers: { ...metadata, counts: { total: 386, enabled: 352, disabled: 34, unknown: 0, missing_logon: 14, controllers: 2 }, findings: computers,
    systems: [{ name: 'Windows 11 Enterprise', count: 226 }, { name: 'Windows 10 Enterprise', count: 84 }, { name: 'Windows Server 2022', count: 48 }, { name: 'Windows Server 2019', count: 20 }, { name: 'Not reported', count: 8 }],
    controllers: ['DC01', 'DC02'].map((name) => ({ name, host: `${name.toLowerCase()}.example.test`, dn: `CN=${name},OU=Domain Controllers,${rootDN}`, os: 'Windows Server 2022', enabled: true })),
  },
};

fixtures.privileged.groups[0].accounts = fixtures.privileged.accounts.slice(0, 2);
fixtures.privileged.groups[1].accounts = [fixtures.privileged.accounts[0], fixtures.privileged.accounts[2]];

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 }, reducedMotion: 'reduce', locale: 'en-US', timezoneId: 'UTC' });
    const errors = []; const requests = [];
    let mode = 'normal'; let delay = 30; let inFlight = 0; let maxInFlight = 0;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol: 'LDAPS', username: 'tester', domain: 'example.test' } });
      if (url.pathname.endsWith('/get/domainobject')) {
        const dn = route.request().postDataJSON().searchbase;
        return route.fulfill({ json: [{ dn, attributes: { name: dn.split(',')[0].slice(3), objectClass: ['top', 'person', 'user'], memberOf: [] } }] });
      }
      if (!url.pathname.includes('/dashboard/')) throw new Error(`Unexpected API request: ${url.pathname}`);
      assert.equal(route.request().method(), 'GET');
      const source = url.pathname.split('/').at(-1);
      requests.push({ source, fresh: url.searchParams.get('fresh') });
      inFlight += 1; maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, delay));
      inFlight -= 1;
      if (mode === 'error' || (mode === 'partial' && source === 'users')) return route.fulfill({ status: 400, json: { error: 'Access denied by directory (fixture)' } });
      const result = structuredClone(fixtures[source]);
      if (mode === 'cached') Object.assign(result, { cached: true, read_at: new Date(Date.now() - 12 * 60000).toISOString() });
      if (mode === 'changed' && source === 'users') result.root_dn = 'DC=other,DC=test';
      if (mode === 'ca' && source === 'inventory') Object.assign(result, { ca_error: 'Insufficient access rights (fixture)', counts: { ...result.counts, cas: null, published_templates: null } });
      if (mode === 'unprotected' && source === 'privileged') Object.assign(result, { protected_users: false, counts: { ...result.counts, unprotected: 2 } });
      if (mode === 'empty') {
        if (result.counts) for (const key of Object.keys(result.counts)) result.counts[key] = 0;
        if (result.findings) for (const finding of Object.values(result.findings)) { finding.count = 0; finding.objects = []; }
        if (result.trusts) result.trusts = [];
        if (result.accounts) { result.accounts = []; result.groups = []; }
        if (result.systems) result.systems = [];
        if (result.controllers) result.controllers = [];
        if (result.policy) { result.policy.lockoutThreshold = 0; result.policy.maxPwdAge = 0; result.policy.minPwdLength = null; }
      }
      return route.fulfill({ json: result });
    });
    const complete = () => page.waitForFunction(() => !document.querySelector('#dashboard-refresh').disabled && !/^(Loading|Refreshing)/.test(document.querySelector('#dashboard-state').textContent));
    const radio = (name) => page.getByRole('radio', { name, exact: true });
    const refresh = async () => { await page.getByRole('button', { name: 'Refresh', exact: true }).click(); await complete(); };

    await page.goto(`${base}/dashboard`);
    await complete();
    assert.deepEqual(requests, ['domain', 'inventory', 'users', 'computers', 'privileged'].map((source) => ({ source, fresh: null })));
    assert.equal(await page.locator('#dashboard-state').getAttribute('role'), null);
    assert.equal(await page.locator('#evidence-count').getAttribute('aria-live'), 'polite');
    assert.equal(await page.locator('#status-message').textContent(), 'Snapshot complete · Current domain, forest-wide CAs · Read-only collection');
    assert.deepEqual(await page.locator('#dashboard-time span').allTextContents(), ['Sep 27, 2026', '10:15:00 AM']);
    assert.equal(await page.locator('#dashboard-live').isHidden(), true);
    assert.equal(await page.locator('#privileged-total').textContent(), '3');
    assert.deepEqual(await page.locator('#dashboard-signals h3').allTextContents(), ['Credential exposure', 'Account hygiene']);
    assert.equal(await page.locator('#dashboard-signals [role="radio"]').count(), 10);
    assert.equal(await radio('No Kerberos pre-auth 125').getAttribute('aria-checked'), 'true');

    await page.getByRole('tab', { name: 'Privileged access' }).click();
    assert.equal(new URL(page.url()).searchParams.get('view'), 'privileged');
    assert.deepEqual(await page.locator('.dashboard__privileged-aside .dashboard__choices .dashboard__signal-count').allTextContents(), ['3', '2', '1', '1', '1', '0']);
    assert.deepEqual(await page.locator('.dashboard__privileged-aside .dashboard__choices .dashboard__signal').evaluateAll((nodes) => nodes.map((node) => node.dataset.matches)), ['false', 'false', 'true', 'true', 'true', 'false']);
    assert.equal(await radio('Inactive > 90 days 1').count(), 1);
    assert.equal(await radio('Password > 1 year 1').count(), 1);
    assert.deepEqual(await page.locator('.dashboard__privileged-groups li').allInnerTexts(), ['Administrators\n2', 'Domain Admins\n2']);
    assert.equal(await page.locator('.dashboard__privileged-groups a.dashboard__object').count(), 0);
    const privilegedRows = page.locator('.dashboard__privileged-table tbody tr');
    assert.equal(await privilegedRows.count(), 3);
    assert.equal(await privilegedRows.nth(0).locator('td').nth(1).textContent(), 'Administrators, Domain Admins');
    assert.deepEqual(await privilegedRows.nth(0).locator('.state').allTextContents(), []);
    assert.deepEqual(await privilegedRows.nth(1).locator('.state').allTextContents(), ['Inactive', 'Old password', 'Not in Protected Users']);
    assert.equal(await privilegedRows.nth(1).locator('td').nth(2).textContent(), 'Not reported');
    assert.deepEqual(await privilegedRows.nth(2).locator('.state').allTextContents(), ['Disabled']);
    assert.equal(new URL(await privilegedRows.nth(0).locator('a').getAttribute('href'), base).pathname, '/users');
    await radio('All privileged accounts 3').focus();
    await page.keyboard.press('ArrowDown');
    assert.equal(await radio('Enabled accounts 2').evaluate((node) => document.activeElement === node && node.getAttribute('aria-checked') === 'true'), true);
    assert.equal(await privilegedRows.count(), 2);
    assert.equal(new URL(page.url()).searchParams.get('accounts'), 'enabled');
    assert.equal(await page.locator('#privileged-panel .dashboard__evidence-footer').textContent(), '2 sampled accounts · 2 total matches');
    await page.keyboard.press('Home');
    assert.equal(await privilegedRows.count(), 3);
    const railStyle = await page.addStyleTag({ content: '.dashboard__privileged-aside { max-height: 180px; }' });
    const rail = page.locator('.dashboard__privileged-aside');
    await rail.evaluate((node) => { node.scrollTop = node.scrollHeight; });
    const railScroll = await rail.evaluate((node) => node.scrollTop);
    assert.ok(railScroll > 0);
    await radio('Administrators 2').click();
    assert.equal(await rail.evaluate((node) => node.scrollTop), railScroll);
    assert.equal(await radio('Administrators 2').evaluate((node) => document.activeElement === node), true);
    await page.keyboard.press('ArrowDown');
    assert.equal(await radio('Domain Admins 2').getAttribute('aria-checked'), 'true');
    assert.equal(await rail.evaluate((node) => node.scrollTop), railScroll);
    await radio('Password never expires 0').click();
    assert.equal(await rail.evaluate((node) => node.scrollTop), railScroll);
    await page.evaluate(() => document.activeElement.blur());
    await radio('Administrators 2').dispatchEvent('click');
    assert.equal(await rail.evaluate((node) => node.scrollTop), railScroll, 'selection without focus must preserve scroll');
    await refresh();
    assert.equal(await rail.evaluate((node) => node.scrollTop), railScroll, 'refresh must preserve sidebar scroll');
    await railStyle.evaluate((node) => node.remove());
    const beforeGroup = requests.length;
    await radio('Domain Admins 2').click();
    assert.equal(await page.locator('#privileged-title').textContent(), 'Domain Admins');
    assert.deepEqual(await privilegedRows.locator('td:first-child').allTextContents(), ['alice.admin', 'old.admin']);
    assert.equal(new URL(page.url()).searchParams.get('accounts'), `group:CN=Domain Admins,CN=Users,${rootDN}`);
    assert.equal(requests.length, beforeGroup);
    const details = page.getByRole('link', { name: 'View group details' });
    assert.equal(await details.getAttribute('data-inspect-dn'), `CN=Domain Admins,CN=Users,${rootDN}`);
    await details.click();
    await page.locator('#object-panel .property-grid').waitFor();
    assert.equal(new URL(await page.locator('#panel-explorer').getAttribute('href')).searchParams.get('dn'), `CN=Domain Admins,CN=Users,${rootDN}`);
    await page.locator('#panel-close').click();
    await radio('Domain Admins 2').press('Home');
    assert.equal(await privilegedRows.count(), 3);
    const assessmentHeight = await page.locator('.dashboard__review').evaluate((node) => node.offsetHeight);
    const requestCount = requests.length;
    await page.getByRole('tab', { name: 'Privileged access' }).press('ArrowLeft');
    assert.equal(await page.getByRole('tab', { name: 'Review queue' }).getAttribute('aria-selected'), 'true');
    assert.equal(await page.locator('#privileged-panel').isHidden(), true);
    assert.equal(await page.locator('.dashboard__review').evaluate((node) => node.offsetHeight), assessmentHeight);
    assert.equal(requests.length, requestCount);
    assert.equal(maxInFlight, 1);
    assert.equal(await page.locator('[data-count="users"]').textContent(), '1,428');
    assert.equal(await page.locator('[data-detail="users"]').textContent(), '1,214 enabled\u00a0· 208 disabled\u00a0· 6 unknown');
    assert.equal(await page.locator('[data-detail="groups"]').count(), 0);
    const authorities = page.locator('#dashboard-inventory a', { hasText: 'Certificate authorities' });
    assert.equal(await authorities.getAttribute('href'), '/ca?view=authorities');
    assert.equal(await page.locator('[data-count="cas"]').textContent(), '2');
    assert.equal(await page.locator('[data-detail="cas"]').textContent(), 'Forest-wide\u00a0· 12 templates published');
    assert.equal(await page.locator('[data-count="trusts"]').count(), 0);
    assert.equal(await page.locator('#dashboard-domain').textContent(), 'example.test');
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot complete');
    assert.equal(await page.locator('#evidence-title').textContent(), 'No Kerberos pre-auth');
    assert.equal(await page.locator('#evidence-flag').textContent(), 'DONT_REQ_PREAUTH');
    assert.deepEqual(await page.locator('#evidence-head th').allTextContents(), ['Account', 'Password set', 'Last logon']);
    assert.equal(await page.locator('#evidence-rows tr').count(), 100);
    assert.equal(await page.locator('#evidence-rows a').count(), 100);
    assert.deepEqual(await page.locator('#evidence-rows tr').first().locator('td').allTextContents(), ['svc.backup', 'Never', 'Aug 23, 2025']);
    assert.equal(await page.locator('#evidence-rows tr').nth(2).locator('td').nth(2).textContent(), 'Not reported');
    assert.equal(await page.locator('#evidence-count').textContent(), '100 sampled objects, oldest password first · 125 total matches');
    const viewAll = new URL(await page.locator('#evidence-all').getAttribute('href'), base);
    assert.equal(await page.locator('#evidence-all').textContent(), 'View all 125 in Users');
    assert.deepEqual([viewAll.pathname, viewAll.searchParams.get('ldapfilter')], ['/users', users.users_preauth.ldap_filter]);
    const layout = () => page.evaluate(() => {
      const review = document.querySelector('.dashboard__review').getBoundingClientRect();
      return {
        height: review.height,
        signals: document.querySelector('#dashboard-signals').getBoundingClientRect().height,
        infrastructure: document.querySelector('.dashboard__infrastructure').getBoundingClientRect().top - review.top,
      };
    });
    const initialLayout = await layout();
    assert.equal(initialLayout.height, 440);
    const scroller = page.locator('.dashboard__table-scroll');
    assert.equal(await scroller.evaluate((node) => node.scrollHeight > node.clientHeight), true);
    await scroller.evaluate((node) => { node.scrollTop = node.scrollHeight; });
    const scrollBounds = await scroller.boundingBox();
    const lastBounds = await page.locator('#evidence-rows tr').last().boundingBox();
    assert.ok(lastBounds.y >= scrollBounds.y && lastBounds.y + lastBounds.height <= scrollBounds.y + scrollBounds.height + 1);
    assert.ok(Math.abs((await page.locator('.dashboard__table th').first().boundingBox()).y - scrollBounds.y) < 2);
    assert.equal(await page.locator('#evidence-rows img').count(), 0);
    const link = page.locator('#evidence-rows tr').nth(1).locator('a').first();
    assert.equal(new URL(await link.getAttribute('href')).searchParams.get('dn'), users.users_preauth.objects[1].dn);
    const dashboardURL = page.url();
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 1100 });
      for (const selector of ['#evidence-rows a', '#dashboard-controllers a', '#dashboard-trust-list a', '#dashboard-domain-link']) {
        const target = page.locator(selector).first();
        const dn = await target.getAttribute('data-inspect-dn');
        await target.click();
        await page.locator('#object-panel .property-grid').waitFor();
        assert.equal(page.url(), dashboardURL);
        assert.equal(new URL(await page.locator('#panel-explorer').getAttribute('href')).searchParams.get('dn'), dn);
        assert.equal(await page.locator('.dashboard__scroll').evaluate((node) => node.inert), width <= 1100);
        assert.equal(await target.getAttribute('aria-current'), 'true');
        if (width === 1440 && selector === '#evidence-rows a') {
          assert.equal(await page.locator('#evidence-rows tr.is-inspected').count(), 1);
          const next = page.locator('#evidence-rows tr').nth(1).locator('a').first();
          await next.click({ timeout: 1500 });
          assert.equal(new URL(await page.locator('#panel-explorer').getAttribute('href')).searchParams.get('dn'), await next.getAttribute('data-inspect-dn'));
          assert.equal(await page.locator('#evidence-rows tr').nth(1).evaluate((node) => node.classList.contains('is-inspected')), true);
          await page.setViewportSize({ width: 390, height: 1100 });
          await page.waitForFunction(() => document.querySelector('.dashboard__scroll').inert);
          await page.setViewportSize({ width, height: 1100 });
          await page.waitForFunction(() => !document.querySelector('.dashboard__scroll').inert);
          await target.click();
        }
        const bounds = await page.locator('#object-panel').boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        if (process.env.DASHBOARD_SCREENSHOT_DIR && selector === '#evidence-rows a') {
          await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOT_DIR}/inspector-${width}.png`, animations: 'disabled' });
        }
        await page.keyboard.press('Escape');
        assert.equal(await page.locator('#object-panel').isHidden(), true);
        assert.equal(await target.evaluate((node) => document.activeElement === node), true);
        assert.equal(await page.locator('.dashboard__scroll [aria-current]').count(), 0);
      }
    }
    await page.getByRole('tab', { name: 'Privileged access' }).click();
    assert.equal(await page.locator('.dashboard__privileged-table th').nth(1).isVisible(), false);
    const notes = await page.locator('.dashboard__privileged-table tbody tr').nth(1).locator('td').last().boundingBox();
    assert.ok(notes.x + notes.width <= 390);
    assert.equal(await page.locator('.dashboard__privileged-aside').evaluate((node) => node.scrollHeight <= node.clientHeight), true);
    assert.equal(await page.locator('.dashboard__privileged-content').evaluate((node) => node.scrollHeight <= node.clientHeight), true);
    assert.equal(await page.locator('#privileged-description').isVisible(), true);
    await page.getByRole('tab', { name: 'Review queue' }).click();
    assert.equal(await page.locator('#evidence-description').isVisible(), true);
    assert.equal(await page.locator('#dashboard-signals .dashboard__signal').evaluateAll((nodes) => nodes.every((node) => node.getBoundingClientRect().height >= 40)), true);
    await page.setViewportSize({ width: 1440, height: 1100 });
    await page.getByLabel('Filter sampled objects').fill('svc.backup');
    assert.equal(await page.locator('#evidence-rows tr').count(), 1);
    assert.equal(await page.locator('#evidence-count').textContent(), '1 of 100 sampled objects, oldest password first · 125 total matches');
    assert.deepEqual(await layout(), initialLayout);
    assert.equal(await scroller.evaluate((node) => node.scrollTop), 0);
    await page.getByLabel('Filter sampled objects').fill('never');
    assert.equal(await page.locator('#evidence-rows tr').count(), 1);
    await page.getByLabel('Filter sampled objects').fill('no such object');
    assert.match(await page.locator('#evidence-empty').textContent(), /No sampled objects/);
    assert.deepEqual(await layout(), initialLayout);
    await page.getByLabel('Filter sampled objects').fill('');
    await radio('Constrained delegation 8').click();
    assert.equal(await page.locator('#evidence-title').textContent(), 'Constrained delegation');
    assert.deepEqual(await page.locator('#evidence-head th').allTextContents(), ['Account', 'Delegation target', 'Last logon']);
    assert.deepEqual(await page.locator('#evidence-rows tr').first().locator('td').allTextContents(), ['APP01$', 'HTTP/backend.example.test', 'May 30, 2026']);
    assert.match(await page.locator('#evidence-count').textContent(), /, by name · 8 total matches$/);
    assert.equal(await page.locator('#evidence-all').textContent(), 'View all 8 in Computers');
    assert.deepEqual(await layout(), initialLayout);
    assert.match(page.url(), /signal=computers_constrained/);
    await radio('Constrained delegation 8').press('ArrowUp');
    assert.equal(await radio('Unconstrained delegation 3').getAttribute('aria-checked'), 'true');
    await radio('No Kerberos pre-auth 125').click();
    await page.getByLabel('Filter sampled objects').fill('svc.web');
    await page.getByRole('button', { name: 'More actions' }).click();
    const downloadEvent = page.waitForEvent('download');
    await page.getByRole('menuitem', { name: 'Export JSON' }).click();
    const download = await downloadEvent;
    const snapshot = JSON.parse(await fs.readFile(await download.path(), 'utf8'));
    assert.equal(snapshot.sources.users.findings.users_preauth.count, 125);
    assert.equal(snapshot.sources.users.findings.users_preauth.objects.length, 100);
    assert.equal(snapshot.sources.users.read_at, collected);
    assert.match(snapshot.limitations, /not proof/);
    assert.match(snapshot.limitations, /up to 100 objects per signal/);
    assert.match(snapshot.scope, /certificate authorities and published templates, which are forest-wide/);
    assert.deepEqual(snapshot.errors, {});
    if (process.env.DASHBOARD_SCREENSHOT_DIR) {
      for (const [name, viewport, theme] of [
        ['desktop-light', { width: 1440, height: 1100 }, 'light'],
        ['desktop-dark', { width: 1440, height: 1100 }, 'dark'],
        ['mobile-light', { width: 390, height: 844 }, 'light'],
        ['mobile-dark', { width: 390, height: 844 }, 'dark'],
      ]) {
        await page.setViewportSize(viewport);
        await page.emulateMedia({ colorScheme: theme });
        await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOT_DIR}/${name}.png`, animations: 'disabled', fullPage: true });
        await page.getByRole('tab', { name: 'Privileged access' }).click();
        await radio('Domain Admins 2').click();
        await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOT_DIR}/${name}-privileged.png`, animations: 'disabled', fullPage: true });
        await radio('All privileged accounts 3').click();
        await page.getByRole('tab', { name: 'Review queue' }).click();
      }
    }
    for (const viewport of [{ width: 1440, height: 1100 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(viewport);
      for (const tab of ['Privileged access', 'Review queue']) {
        await page.getByRole('tab', { name: tab }).click();
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      }
      if (viewport.width < 720) {
        assert.equal(await page.locator('#dashboard-signals').evaluate((node) => getComputedStyle(node).gridTemplateColumns.split(' ').length), 2);
        assert.ok((await scroller.boundingBox()).height <= 360);
        assert.equal(await page.locator('.dashboard__tooltip').evaluateAll((nodes) => nodes.filter((node) => node.checkVisibility({ visibilityProperty: true })).every((node) => node.getBoundingClientRect().right <= innerWidth)), true);
      }
    }
    await page.getByLabel('Filter sampled objects').fill('svc.web');
    await page.setViewportSize({ width: 1440, height: 1100 });

    mode = 'normal'; delay = 400; requests.length = 0;
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#dashboard-state').textContent.startsWith('Refreshing'));
    assert.equal(await page.locator('[data-count="users"]').textContent(), '1,428');
    assert.equal(await page.locator('#dashboard-inventory').evaluate((node) => node.classList.contains('is-refreshing')), true);
    assert.equal(await page.locator('#evidence-rows .loading-row').count(), 0);
    await complete();
    delay = 30;
    assert.deepEqual(requests.map((item) => item.fresh), Array(5).fill('1'));
    assert.equal(await page.getByLabel('Filter sampled objects').inputValue(), 'svc.web');
    assert.equal(await page.locator('.dashboard__scroll .is-refreshing').count(), 0);

    mode = 'cached';
    await page.reload();
    await complete();
    assert.equal(await page.locator('#dashboard-time').textContent(), 'Cached · read 12 minutes ago');
    assert.match(await page.locator('#dashboard-time').getAttribute('title'), /^Directory read /);
    mode = 'normal'; requests.length = 0;
    await page.getByRole('button', { name: 'Read live', exact: true }).click();
    await complete();
    assert.deepEqual(requests.map((item) => item.fresh), Array(5).fill('1'));
    assert.equal(await page.locator('#dashboard-live').isHidden(), true);

    mode = 'unprotected';
    await page.goto(`${base}/?view=privileged&accounts=unprotected`);
    await complete();
    assert.equal(await page.getByRole('tab', { name: 'Privileged access' }).getAttribute('aria-selected'), 'true');
    assert.equal(await radio('Protected Users group not found —').isDisabled(), true);
    assert.equal(await radio('All privileged accounts 3').getAttribute('aria-checked'), 'true');
    assert.equal(await page.locator('.dashboard__privileged-table .state', { hasText: 'Not in Protected Users' }).count(), 0);
    mode = 'normal';
    await page.goto(`${base}/?view=privileged&accounts=stale`);
    await complete();
    assert.equal(await radio('Inactive > 90 days 1').getAttribute('aria-checked'), 'true');
    assert.equal(await page.locator('#privileged-description').textContent(), 'Enabled privileged accounts whose replicated lastLogonTimestamp is more than 90 days old. Accounts that never signed in count from their last password change.');
    await page.getByRole('tab', { name: 'Review queue' }).click();

    mode = 'partial';
    await refresh();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Partial snapshot');
    assert.equal(await page.locator('[data-count="users"]').textContent(), '—');
    assert.equal(await page.locator('[data-count="computers"]').textContent(), '386');
    assert.match(await page.locator('#evidence-empty').textContent(), /not been evaluated/);
    assert.equal(await page.locator('#evidence-count').textContent(), 'Not evaluated');
    assert.equal(await page.locator('#evidence-filter').isDisabled(), true);
    assert.equal(await page.locator('#dashboard-errors').textContent(), 'Users unavailable: Access denied by directory (fixture)');
    if (process.env.DASHBOARD_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOT_DIR}/partial.png`, animations: 'disabled' });
    mode = 'normal'; requests.length = 0;
    await page.locator('#evidence-empty').getByRole('button', { name: 'Retry', exact: true }).click();
    await complete();
    assert.deepEqual(requests, [{ source: 'users', fresh: '1' }]);
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot complete');
    assert.equal(await page.locator('#dashboard-errors').isHidden(), true);
    mode = 'ca';
    await refresh();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Partial snapshot');
    assert.equal(await page.locator('#dashboard-errors').textContent(), 'Certificate authorities unavailable: Insufficient access rights (fixture)');
    assert.equal(await page.locator('[data-count="users"]').textContent(), '1,428');
    assert.equal(await page.locator('[data-count="cas"]').textContent(), '—');
    assert.equal(await page.locator('[data-detail="cas"]').textContent(), 'Unavailable');
    assert.equal(await page.locator('[data-detail="cas"]').getAttribute('title'), 'Insufficient access rights (fixture)');
    assert.equal(await page.locator('[data-count="groups"]').textContent(), '248');
    mode = 'empty';
    await refresh();
    assert.equal(await page.locator('[data-count="users"]').textContent(), '0');
    assert.equal(await page.locator('[data-detail="cas"]').textContent(), 'Forest-wide\u00a0· none registered');
    assert.match(await page.locator('#evidence-empty').textContent(), /No matches/);
    assert.equal(await page.locator('#evidence-all').isHidden(), true);
    assert.match(await page.locator('#dashboard-policy').textContent(), /Not readable/);
    assert.match(await page.locator('#dashboard-policy').textContent(), /No lockout/);
    assert.match(await page.locator('#dashboard-policy').textContent(), /No expiry/);
    assert.equal(await page.locator('#dashboard-systems').innerText(), 'No computers returned.');
    mode = 'error';
    await refresh();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot unavailable');
    assert.equal(await page.locator('#dashboard-domain-link').isHidden(), true);
    assert.equal(await page.locator('#dashboard-context').textContent(), '');
    assert.equal(await page.locator('#dashboard-export').isDisabled(), true);
    assert.equal(await page.locator('#dashboard-errors p').count(), 1);
    assert.equal(await page.locator('#dashboard-errors').textContent(), 'Domain policy, Directory inventory, Users, Computers, and Privileged access unavailable: Access denied by directory (fixture)');
    assert.equal(await page.locator('.dashboard__scroll').getByRole('button', { name: 'Retry', exact: true }).count(), 5);
    mode = 'changed';
    await refresh();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot unavailable');
    assert.equal(await page.locator('#dashboard-domain-link').isHidden(), true);
    assert.match(await page.locator('#dashboard-errors').textContent(), /domain changed/);
    assert.equal(await page.locator('[data-count="groups"]').textContent(), '—');
    mode = 'normal';
    await refresh();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot complete');
    assert.equal(await page.locator('#dashboard-errors').isHidden(), true);
    await radio('Computer logon > 90 days 27').focus();
    await page.keyboard.press('Enter');
    assert.equal(await page.locator('#evidence-title').textContent(), 'Computer logon > 90 days');
    assert.equal(await page.locator('#evidence-flag').textContent(), 'lastLogonTimestamp');
    await page.goto(`${base}/?view=privileged&accounts=${encodeURIComponent(`group:CN=Domain Admins,CN=Users,${rootDN}`)}`);
    await page.waitForFunction(() => document.querySelector('#dashboard-state').textContent === 'Snapshot complete');
    assert.equal(await page.locator('#privileged-title').textContent(), 'Domain Admins');
    assert.equal(await radio('Domain Admins 2').getAttribute('aria-checked'), 'true');
    assert.deepEqual(errors, []);
    console.log('Dashboard browser checks passed: read-only serial collection, grouped signals with radio keyboard navigation, per-signal evidence columns, linked full result sets, inspected rows, stale-while-refreshing snapshots, cache freshness, missing Protected Users, per-source retry, grouped errors, export, partial/empty/error states, session changes, responsive layout and safe rendering.');
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
