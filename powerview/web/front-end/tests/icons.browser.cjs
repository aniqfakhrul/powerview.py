const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const computer = (name, userAccountControl) => ({ dn: `CN=${name},OU=Computers,${root}`, attributes: {
  name, sAMAccountName: `${name}$`, userAccountControl, objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer'],
  memberOf: [`CN=Domain Controllers,CN=Users,${root}`, `CN=Servers,OU=Groups,${root}`],
} });
const computers = [computer('DC01', 532480), computer('WS01', 4096)];
const iconOf = (locator) => locator.locator('svg:visible use').first().getAttribute('href').then((href) => href.split('#')[1]);

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 800 } });
    const errors = [];
    const lookups = [];
    let release = () => {};
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      const data = route.request().postDataJSON();
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
      if (path.endsWith('/get/domaincomputer')) return route.fulfill({ json: computers });
      if (path.endsWith('/get/domainobject') && data?.size_limit) {
        lookups.push(data);
        const wanted = data.properties.map((name) => name.toLowerCase());
        return route.fulfill({ json: computers.map(({ dn, attributes }) => ({ dn, attributes: Object.fromEntries(Object.entries(attributes).filter(([key]) => wanted.includes(key.toLowerCase()))) })) });
      }
      if (path.endsWith('/get/domainobject')) {
        await new Promise((resolve) => { release = resolve; });
        const found = computers.find((item) => item.dn === data.searchbase);
        const formatted = found.attributes.userAccountControl === 532480 ? ['SERVER_TRUST_ACCOUNT', 'TRUSTED_FOR_DELEGATION'] : ['WORKSTATION_TRUST_ACCOUNT'];
        return route.fulfill({ json: [{ ...found, attributes: { ...found.attributes, userAccountControl: formatted } }] });
      }
      return route.fulfill({ json: { available: false, attributes: [] } });
    });

    await page.goto(`${base}/computers`);
    const row = (name) => page.locator('#grid-body tr[data-dn]', { hasText: name });
    await row('DC01').waitFor();
    assert.equal(await iconOf(row('DC01').locator('.cell-name')), 'server');
    assert.equal(await iconOf(row('WS01').locator('.cell-name')), 'computer');

    const title = page.locator('[data-panel-title]');
    for (const [name, expected] of [['DC01', 'server'], ['WS01', 'computer']]) {
      await row(name).click();
      await title.locator('h1', { hasText: name }).waitFor();
      assert.equal(await title.locator('svg').count(), 0, `${name} shows an icon before its type is known`);
      release();
      await title.locator('.object-title__copy').waitFor();
      assert.equal(await iconOf(title), expected);
    }
    await page.getByRole('tab', { name: /^Member of/ }).click();
    const memberOf = page.locator('.membership:not([hidden]) .membership__item');
    await memberOf.first().waitFor();
    assert.deepEqual(await memberOf.evaluateAll((items) => items.map((item) => item.querySelector('use').getAttribute('href').split('#')[1])), ['group', 'group']);

    await page.goto(`${base}/pathfinder`);
    assert.equal(await iconOf(page.locator('.toolbar__title')), 'pathfinder');
    await page.locator('#pathfinder-target').fill('DC');
    const options = page.getByRole('listbox').getByRole('option');
    await options.first().waitFor();
    assert.ok(lookups.at(-1).properties.includes('userAccountControl'));
    assert.deepEqual(await options.evaluateAll((items) => items.map((item) => item.querySelector('use').getAttribute('href').split('#')[1])), ['server', 'computer']);

    await page.route('**/api/dashboard/**', (route) => route.fulfill({ status: 400, json: { error: 'unavailable' } }));
    await page.goto(`${base}/dashboard`);
    assert.equal(await iconOf(page.locator('.dashboard__toolbar h1')), 'dashboard');
    assert.deepEqual(errors, []);
    console.log('PASS: controller and workstation icons in grid, panel and search suggestions, no placeholder icon while loading, Member of group icons, Pathfinder and Dashboard titles match the sidebar.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
