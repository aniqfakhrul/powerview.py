const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const collected = '2026-09-27T10:15:00+00:00';
const metadata = { domain: 'example.test', root_dn: rootDN, dc: 'dc01.example.test', collected_at: collected, sample_limit: 100 };
const names = ['svc.backup', 'svc.sql', 'svc.deploy', 'svc.reports', 'svc.legacy', 'svc.web'];
const object = (index) => ({ name: names[index] ?? `service.${String(index).padStart(3, '0')}`, dn: `CN=Service ${index},OU=Service Accounts,${rootDN}`, evidence: 'DONT_REQ_PREAUTH is set' });
const users = Object.fromEntries(['preauth', 'spn', 'password_not_required', 'never_expires', 'admin', 'stale'].map((key, index) => [`users_${key}`, {
  count: [125, 34, 3, 82, 16, 41][index], objects: Array.from({ length: Math.min([125, 34, 3, 82, 16, 41][index], 100) }, (_, item) => ({ ...object(item), evidence: ['DONT_REQ_PREAUTH is set', 'MSSQLSvc/sql.example.test:1433', 'PASSWD_NOTREQD is set', 'DONT_EXPIRE_PASSWORD is set', 'adminCount = 1', 'Last replicated logon: 2025-12-19'][index] })),
}]));
const computers = Object.fromEntries(['unconstrained', 'constrained', 'password_not_required', 'stale'].map((key, index) => [`computers_${key}`, {
  count: [3, 8, 1, 27][index], objects: [{ name: 'APP01$', dn: `CN=APP01,OU=Servers,${rootDN}`, evidence: ['TRUSTED_FOR_DELEGATION; not a domain controller', 'HTTP/backend.example.test', 'PASSWD_NOTREQD is set', 'Last replicated logon: 2025-10-12'][index] }],
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

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 }, reducedMotion: 'reduce' });
    const errors = []; const requests = [];
    let mode = 'normal'; let inFlight = 0; let maxInFlight = 0;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol: 'LDAPS', username: 'tester', domain: 'example.test' } });
      if (path.endsWith('/get/domainobject')) {
        const dn = route.request().postDataJSON().searchbase;
        return route.fulfill({ json: [{ dn, attributes: { name: dn.split(',')[0].slice(3), objectClass: ['top', 'person', 'user'], memberOf: [] } }] });
      }
      if (!path.includes('/dashboard/')) throw new Error(`Unexpected API request: ${path}`);
      assert.equal(route.request().method(), 'GET');
      const source = path.split('/').at(-1);
      requests.push(source);
      inFlight += 1; maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 30));
      inFlight -= 1;
      if (mode === 'error' || (mode === 'partial' && source === 'users')) return route.fulfill({ status: 400, json: { error: 'Access denied by directory (fixture)' } });
      const result = structuredClone(fixtures[source]);
      if (mode === 'changed' && source === 'users') result.root_dn = 'DC=other,DC=test';
      if (mode === 'ca' && source === 'inventory') Object.assign(result, { ca_error: 'Insufficient access rights (fixture)', counts: { ...result.counts, cas: null, published_templates: null } });
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
    const complete = () => page.waitForFunction(() => !document.querySelector('#dashboard-refresh').disabled && document.querySelector('#dashboard-state').textContent !== 'Loading snapshot…');
    await page.goto(`${base}/dashboard`);
    await complete();
    assert.deepEqual(requests, ['domain', 'inventory', 'users', 'computers', 'privileged']);
    assert.equal(await page.locator('#privileged-total').textContent(), '3');
    await page.getByRole('tab', { name: 'Privileged access' }).click();
    assert.deepEqual(await page.locator('.dashboard__privileged-aside .dashboard__signal-count').allTextContents(), ['3', '2', '1', '1', '1', '0']);
    assert.deepEqual(await page.locator('.dashboard__privileged-aside .dashboard__signal').evaluateAll((nodes) => nodes.map((node) => node.dataset.matches)), ['false', 'false', 'true', 'true', 'true', 'false']);
    assert.equal(await page.getByRole('button', { name: 'Logon > 90 days 1', exact: true }).count(), 1);
    assert.deepEqual(await page.locator('.dashboard__privileged-groups li').allInnerTexts(), ['Administrators\n2', 'Domain Admins\n2']);
    const privilegedRows = page.locator('.dashboard__privileged-table tbody tr');
    assert.equal(await privilegedRows.count(), 3);
    assert.equal(await privilegedRows.nth(0).locator('td').nth(1).textContent(), 'Administrators, Domain Admins');
    assert.deepEqual(await privilegedRows.nth(0).locator('.state').allTextContents(), []);
    assert.deepEqual(await privilegedRows.nth(1).locator('.state').allTextContents(), ['No recent logon', 'Old password', 'Not in Protected Users']);
    assert.equal(await privilegedRows.nth(1).locator('td').nth(2).textContent(), 'Not reported');
    assert.deepEqual(await privilegedRows.nth(2).locator('.state').allTextContents(), ['Disabled']);
    assert.equal(new URL(await privilegedRows.nth(0).locator('a').getAttribute('href'), base).pathname, '/users');
    await page.getByRole('button', { name: 'Enabled accounts 2', exact: true }).click();
    assert.equal(await privilegedRows.count(), 2);
    await page.getByRole('button', { name: 'All privileged accounts 3', exact: true }).click();
    const assessmentHeight = await page.locator('.dashboard__review').evaluate((node) => node.offsetHeight);
    const requestCount = requests.length;
    await page.getByRole('tab', { name: 'Privileged access' }).press('ArrowLeft');
    assert.equal(await page.getByRole('tab', { name: 'Review queue' }).getAttribute('aria-selected'), 'true');
    assert.equal(await page.locator('#privileged-panel').isHidden(), true);
    assert.equal(await page.locator('.dashboard__review').evaluate((node) => node.offsetHeight), assessmentHeight);
    assert.equal(requests.length, requestCount);
    assert.equal(maxInFlight, 1);
    assert.equal(await page.locator('[data-count="users"]').textContent(), '1,428');
    const authorities = page.locator('#dashboard-inventory a', { hasText: 'Certificate authorities' });
    assert.equal(await authorities.getAttribute('href'), '/ca?view=authorities');
    assert.equal(await page.locator('[data-count="cas"]').textContent(), '2');
    assert.equal(await page.locator('[data-detail="cas"]').textContent(), 'Forest-wide · 12 templates published');
    assert.equal(await page.locator('[data-count="trusts"]').count(), 0);
    assert.equal(await page.locator('#dashboard-domain').textContent(), 'example.test');
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot complete');
    assert.equal(await page.locator('#evidence-rows tr').count(), 100);
    assert.equal(await page.locator('#evidence-count').textContent(), '100 sampled objects · 125 total matches');
    assert.equal(await page.getByRole('button', { name: 'Next objects' }).count(), 0);
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
        if (width === 1440 && selector === '#evidence-rows a') {
          const next = page.locator('#evidence-rows tr').nth(1).locator('a').first();
          await next.click({ timeout: 1500 });
          assert.equal(new URL(await page.locator('#panel-explorer').getAttribute('href')).searchParams.get('dn'), await next.getAttribute('data-inspect-dn'));
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
      }
    }
    await page.getByRole('tab', { name: 'Privileged access' }).click();
    assert.equal(await page.locator('.dashboard__privileged-table th').nth(1).isVisible(), false);
    const notes = await page.locator('.dashboard__privileged-table tbody tr').nth(1).locator('td').last().boundingBox();
    assert.ok(notes.x + notes.width <= 390);
    assert.equal(await page.locator('.dashboard__privileged-aside').evaluate((node) => node.scrollHeight <= node.clientHeight), true);
    assert.equal(await page.locator('.dashboard__privileged-content').evaluate((node) => node.scrollHeight <= node.clientHeight), true);
    await page.getByRole('tab', { name: 'Review queue' }).click();
    await page.setViewportSize({ width: 1440, height: 1100 });
    await page.getByLabel('Filter sampled objects').fill('svc.backup');
    assert.equal(await page.locator('#evidence-rows tr').count(), 1);
    assert.equal(await page.locator('#evidence-count').textContent(), '1 of 100 sampled objects · 125 total matches');
    assert.deepEqual(await layout(), initialLayout);
    assert.equal(await scroller.evaluate((node) => node.scrollTop), 0);
    await page.getByLabel('Filter sampled objects').fill('no such object');
    assert.match(await page.locator('#evidence-empty').textContent(), /No sampled objects/);
    assert.deepEqual(await layout(), initialLayout);
    await page.getByLabel('Filter sampled objects').fill('');
    await page.getByRole('button', { name: 'Constrained delegation 8', exact: true }).click();
    assert.equal(await page.locator('#evidence-title').textContent(), 'Constrained delegation');
    assert.deepEqual(await layout(), initialLayout);
    assert.match(page.url(), /signal=computers_constrained/);
    await page.getByRole('button', { name: 'No Kerberos pre-auth 125', exact: true }).click();
    const downloadEvent = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export snapshot' }).click();
    const download = await downloadEvent;
    const snapshot = JSON.parse(await fs.readFile(await download.path(), 'utf8'));
    assert.equal(snapshot.sources.users.findings.users_preauth.count, 125);
    assert.equal(snapshot.sources.users.findings.users_preauth.objects.length, 100);
    assert.match(snapshot.limitations, /not proof/);
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
        await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOT_DIR}/${name}-privileged.png`, animations: 'disabled', fullPage: true });
        if (viewport.width < 720) {
          await page.locator('.dashboard__privileged-accounts').scrollIntoViewIfNeeded();
          await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOT_DIR}/${name}-privileged-table.png`, animations: 'disabled' });
        }
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        await page.getByRole('tab', { name: 'Review queue' }).click();
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        if (name.startsWith('mobile')) {
          assert.equal(await page.locator('#dashboard-signals').evaluate((node) => getComputedStyle(node).gridTemplateColumns.split(' ').length), 2);
          assert.ok((await scroller.boundingBox()).height <= 288);
          assert.equal(await scroller.evaluate((node) => node.scrollHeight > node.clientHeight), true);
        }
        if (name === 'mobile-dark') {
          await page.locator('.dashboard__scroll').evaluate((node) => { node.scrollTop = node.scrollHeight; });
          await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOT_DIR}/mobile-infrastructure.png`, animations: 'disabled' });
          await page.locator('.dashboard__scroll').evaluate((node) => { node.scrollTop = 0; });
        }
      }
    }
    await page.setViewportSize({ width: 1440, height: 1100 });
    mode = 'partial';
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await complete();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Partial snapshot');
    assert.equal(await page.locator('[data-count="users"]').textContent(), '—');
    assert.equal(await page.locator('[data-count="computers"]').textContent(), '386');
    assert.match(await page.locator('#evidence-empty').textContent(), /not been evaluated/);
    assert.match(await page.locator('#evidence-count').textContent(), /Source unavailable/);
    assert.equal(await page.locator('#evidence-filter').isDisabled(), true);
    assert.match(await page.locator('#dashboard-errors').textContent(), /Access denied/);
    if (process.env.DASHBOARD_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.DASHBOARD_SCREENSHOT_DIR}/partial.png`, animations: 'disabled' });
    mode = 'ca';
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await complete();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Partial snapshot');
    assert.equal(await page.locator('#dashboard-errors').textContent(), 'Certificate authorities unavailable: Insufficient access rights (fixture)');
    assert.equal(await page.locator('[data-count="users"]').textContent(), '1,428');
    assert.equal(await page.locator('[data-count="cas"]').textContent(), '—');
    assert.equal(await page.locator('[data-detail="cas"]').textContent(), 'Unavailable');
    assert.equal(await page.locator('[data-detail="cas"]').getAttribute('title'), 'Insufficient access rights (fixture)');
    assert.equal(await page.locator('[data-count="groups"]').textContent(), '248');
    mode = 'empty';
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await complete();
    assert.equal(await page.locator('[data-count="users"]').textContent(), '0');
    assert.equal(await page.locator('[data-detail="cas"]').textContent(), 'Forest-wide · none registered');
    assert.match(await page.locator('#evidence-empty').textContent(), /No matches/);
    assert.match(await page.locator('#dashboard-policy').textContent(), /Not readable/);
    assert.match(await page.locator('#dashboard-policy').textContent(), /No lockout/);
    assert.match(await page.locator('#dashboard-policy').textContent(), /No expiry/);
    mode = 'error';
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await complete();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot unavailable');
    assert.equal(await page.locator('#dashboard-domain-link').isHidden(), true);
    assert.equal(await page.getByRole('button', { name: 'Export snapshot' }).isDisabled(), true);
    mode = 'changed';
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await complete();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot unavailable');
    assert.equal(await page.locator('#dashboard-domain-link').isHidden(), true);
    assert.match(await page.locator('#dashboard-errors').textContent(), /domain changed/);
    assert.equal(await page.locator('[data-count="groups"]').textContent(), '—');
    mode = 'normal';
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await complete();
    assert.equal(await page.locator('#dashboard-state').textContent(), 'Snapshot complete');
    assert.equal(await page.locator('#dashboard-errors').isHidden(), true);
    await page.getByRole('button', { name: 'Computer logon > 90 days 27', exact: true }).focus();
    await page.keyboard.press('Enter');
    assert.equal(await page.locator('#evidence-title').textContent(), 'Computer logon > 90 days');
    assert.deepEqual(errors, []);
    console.log('Dashboard browser checks passed: read-only serial collection, evidence, navigation, bounded scrolling, export, partial/empty/error states, refresh, session changes, responsive layout, keyboard, and safe rendering.');
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
