/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const metadata = { domain: 'example.test', root_dn: rootDN, dc: 'dc01.example.test', collected_at: '2026-09-27T10:15:00+00:00', sample_limit: 100 };
const empty = (keys) => Object.fromEntries(keys.map((key) => [key, { count: 0, objects: [] }]));
const userKeys = ['users_preauth', 'users_spn', 'users_password_not_required', 'users_never_expires', 'users_admin', 'users_stale'];
const computerKeys = ['computers_unconstrained', 'computers_constrained', 'computers_password_not_required', 'computers_stale'];

function fixture(source, days) {
  if (source === 'domain') return { ...metadata, policy: { minPwdLength: 12, pwdHistoryLength: 24, maxPwdAge: 'never', minPwdAge: 86400, lockoutThreshold: 5, lockoutDuration: 'never', pwdProperties: 1, 'ms-DS-MachineAccountQuota': 0 } };
  if (source === 'inventory') return { ...metadata, counts: { groups: 1, ous: 1, gpos: 1, trusts: 0, cas: 1, published_templates: 1 }, trusts: [], ca_error: null };
  if (source === 'users') {
    const findings = empty(userKeys);
    findings.users_spn = { count: 1, objects: [{ name: 'svc.web', dn: `CN=svc.web,OU=Service,${rootDN}`, evidence: 'HTTP/web' }] };
    findings.users_stale = { count: days === 30 ? 4 : 2, objects: [] };
    return { ...metadata, inactive_days: days, counts: { total: 3, enabled: 3, disabled: 0, unknown: 0, missing_logon: 0 }, findings };
  }
  return { ...metadata, inactive_days: days, counts: { total: 1, enabled: 1, disabled: 0, unknown: 0, missing_logon: 0, controllers: 1 }, findings: empty(computerKeys),
    systems: [{ name: 'Windows Server 2022', count: 1 }], controllers: [{ name: 'DC01', host: 'dc01.example.test', dn: `CN=DC01,OU=Domain Controllers,${rootDN}`, os: 'Windows Server 2022', enabled: true }] };
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = []; const requests = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
      const source = url.pathname.split('/').at(-1);
      requests.push({ source, days: url.searchParams.get('days'), fresh: url.searchParams.get('fresh') });
      return route.fulfill({ json: fixture(source, Number(url.searchParams.get('days'))) });
    });
    const relative = async (locator) => { const url = new URL(await locator.getAttribute('href'), base); return `${url.pathname} ${url.searchParams.get('dn')}`; };
    const complete = () => page.waitForFunction(() => document.querySelector('#dashboard-state').textContent === 'Snapshot complete');

    await page.goto(`${base}/dashboard`);
    await complete();
    assert.deepEqual(requests.map((item) => [item.days, item.fresh]), Array(4).fill(['90', null]));
    assert.equal(await page.locator('.dashboard__scope').count(), 0);
    assert.match(await page.locator('#dashboard-export').getAttribute('title'), /account names/);

    await page.locator('.dashboard__signal', { hasText: 'Kerberoastable users' }).click();
    assert.equal(await page.locator('#evidence-total').textContent(), '1 match');
    assert.equal(await relative(page.locator('#evidence-rows a.dashboard__object').first()), `/users CN=svc.web,OU=Service,${rootDN}`);
    assert.match(await relative(page.locator('#evidence-rows a.icon-button').first()), /^\/explorer CN=svc\.web/);
    assert.equal(await relative(page.locator('#dashboard-controllers a').first()), `/computers CN=DC01,OU=Domain Controllers,${rootDN}`);
    assert.equal(await page.locator('[data-detail="cas"]').textContent(), 'Forest-wide · 1 template published');
    const policy = await page.locator('#dashboard-policy').innerText();
    assert.match(policy, /Maximum password age\s+No expiry/);
    assert.match(policy, /Lockout duration\s+Until an administrator unlocks/);
    const zero = page.locator('.dashboard__signal', { hasText: 'No Kerberos pre-auth' }).locator('.dashboard__signal-count');
    assert.notEqual(await zero.evaluate((node) => getComputedStyle(node).color), await page.evaluate(() => getComputedStyle(document.body).getPropertyValue('--color-danger')));

    const tip = page.locator('#evidence-description');
    assert.equal(await tip.isVisible(), false);
    await page.getByRole('button', { name: 'About this signal' }).focus();
    await tip.waitFor();
    assert.match(await tip.textContent(), /crack them offline, so weak passwords are the risk/);
    await page.keyboard.press('Escape');
    await tip.waitFor({ state: 'hidden' });
    await page.getByRole('button', { name: /Default policy/ }).hover();
    await page.locator('#policy-note').waitFor();
    assert.match(await page.locator('#policy-note').textContent(), /Fine-grained password policies/);
    assert.equal(await page.locator('.dashboard__policy .dashboard__note').count(), 0);
    await page.mouse.move(0, 0);

    requests.length = 0;
    await page.getByRole('button', { name: 'Refresh' }).click();
    await page.waitForFunction(() => !document.querySelector('#dashboard-refresh').disabled);
    await complete();
    assert.deepEqual(requests.map((item) => item.fresh), Array(4).fill('1'));

    requests.length = 0;
    await page.locator('#dashboard-days').selectOption('30');
    await complete();
    assert.deepEqual(requests.map((item) => [item.days, item.fresh]), Array(4).fill(['30', null]));
    await page.getByText('User logon > 30 days').waitFor();
    assert.match(await page.locator('.dashboard__signal', { hasText: 'User logon > 30 days' }).innerText(), /4/);
    await page.reload();
    await complete();
    assert.equal(await page.locator('#dashboard-days').inputValue(), '30');

    await page.setViewportSize({ width: 390, height: 844 });
    await page.reload();
    await complete();
    const clipped = await page.$$eval('.dashboard__signal', (nodes) => nodes.filter((node) => node.getBoundingClientRect().right > innerWidth + 1).length);
    assert.equal(clipped, 0);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    assert.deepEqual(errors, []);
    console.log('Dashboard option checks passed: cached first load, fresh Refresh, persisted inactivity threshold with updated labels, typed-page object links, singular match count, never intervals, neutral zero counts, mobile signals within the viewport.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
