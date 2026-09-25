/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const services = `CN=Public Key Services,CN=Services,CN=Configuration,${root}`;
const template = (cn, attributes) => ({ attributes: {
  cn, name: cn, distinguishedName: `CN=${cn},CN=Certificate Templates,${services}`,
  Enabled: false, 'Certificate Authorities': [], Vulnerable: [], 'Enrollment Rights': ['EXAMPLE\\Domain Users'],
  'Client Authentication': false, ManagerApproval: false, pKIExpirationPeriod: '1 year', pKIExtendedKeyUsage: ['Server Authentication'],
  ...attributes,
} });
let templates = [
  template('WebServer', { Enabled: true, 'Certificate Authorities': ['CA-One'] }),
  template('User', { Enabled: true, 'Certificate Authorities': ['CA-One', 'CA-Two'], 'Client Authentication': true, Vulnerable: ["Finding-A - 'EXAMPLE\\Domain Users'"] }),
  template('Unused', { ManagerApproval: undefined }),
];
const authority = (name, published) => ({ dn: `CN=${name},CN=Enrollment Services,${services}`, attributes: {
  name, cn: name, dNSHostName: `${name.toLowerCase()}.example.test`, cACertificateDN: `CN=${name}, DC=example, DC=test`, certificateTemplates: published,
} });
const authorities = [authority('CA-One', ['WebServer', 'User']), authority('CA-Two', ['User']), authority('CA-Three', [])];
const webResults = { 'CA-One': ['http://ca-one.example.test/certsrv'], 'CA-Two': [false, false] };

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const requests = []; const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      const data = route.request().postDataJSON();
      requests.push({ path, data });
      if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK', protocol: 'LDAPS' } });
      if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
      if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root, `CN=Configuration,${root}`] } } });
      if (path.endsWith('/get/domaincatemplate')) return route.fulfill({ json: templates });
      if (path.endsWith('/get/domainca')) return route.fulfill({ json: data.check_all
        ? authorities.map((item) => ({ ...item, attributes: { ...item.attributes, ...(webResults[item.attributes.name] ? { WebEnrollment: webResults[item.attributes.name] } : {}) } }))
        : authorities });
      if (path.endsWith('/get/domainobject')) return route.fulfill({ json: [{ dn: data.searchbase, attributes: { name: 'object', objectClass: ['pKICertificateTemplate'] } }] });
      throw new Error(`Unexpected API request: ${path}`);
    });
    const rows = page.locator('#grid-body tr[data-dn]');
    const names = () => rows.locator('.cell-name span').allTextContents();

    await page.goto(`${base}/ca`);
    await rows.first().waitFor();
    assert.deepEqual(requests.find(({ path }) => path.endsWith('/get/domaincatemplate')).data, { resolve_sids: true, no_cache: false });
    assert.equal(await page.locator('#grid-count').textContent(), '3 templates');
    assert.equal(await page.locator('.view-switch [aria-current="page"]').textContent(), 'Templates');
    assert.deepEqual(await page.locator('#grid-head .column-sort__label').allTextContents(), ['name', 'Enabled', 'Certificate Authorities', 'pKIExtendedKeyUsage', 'Client Authentication', 'ManagerApproval', 'pKIExpirationPeriod', 'Enrollment Rights (count)', 'Vulnerable']);
    const user = rows.filter({ hasText: 'User' });
    assert.match(await user.innerText(), /Enabled\s+CA-One; CA-Two/);
    assert.equal(await user.locator('.state--danger').textContent(), '1');
    const approval = async (name) => rows.filter({ hasText: name }).locator('td').nth(6).innerText();
    assert.equal(await user.locator('td').nth(5).innerText(), 'Yes');
    assert.equal(await rows.filter({ hasText: 'WebServer' }).locator('td').nth(5).innerText(), 'No');
    assert.equal(await approval('WebServer'), 'No');
    assert.equal(await approval('Unused'), '—');
    assert.match(await rows.filter({ hasText: 'Unused' }).innerText(), /Disabled/);
    assert.deepEqual(await page.locator('#ca-authority option').allTextContents(), ['All templates', 'CA-One', 'CA-Two', 'Not published']);

    await page.locator('#ca-authority').selectOption('CA-Two');
    await page.waitForFunction(() => document.querySelector('#grid-count').textContent === '1 template');
    assert.deepEqual(await names(), ['User']);
    await page.locator('#ca-authority').selectOption('-');
    await page.waitForFunction(() => document.querySelector('#grid-count').textContent === '1 template');
    assert.deepEqual(await names(), ['Unused']);
    await page.locator('#ca-authority').selectOption('');
    await page.locator('#ca-state').selectOption('findings');
    await page.waitForFunction(() => document.querySelector('#grid-count').textContent === '1 template');
    assert.equal(new URL(page.url()).searchParams.get('state'), 'findings');
    assert.equal(requests.filter(({ path }) => path.endsWith('/get/domaincatemplate')).length, 1);

    await page.locator('#ca-state').selectOption('');
    await page.waitForFunction(() => document.querySelector('#grid-count').textContent === '3 templates');
    await rows.filter({ hasText: 'User' }).click();
    await page.getByRole('tab', { name: 'Summary', exact: true }).click();
    const summary = page.locator('#object-panel .properties:visible');
    await summary.getByText("Finding-A - 'EXAMPLE\\Domain Users'").waitFor();
    assert.match(await summary.innerText(), /Certificate Authorities\s+CA-One\s+CA-Two/);
    templates = templates.map((item) => (item.attributes.cn === 'User' ? { attributes: { ...item.attributes, Vulnerable: [], 'Enrollment Rights': ['EXAMPLE\\Admins'] } } : item));
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await summary.getByText('EXAMPLE\\Admins').waitFor();
    assert.equal(await summary.getByText("Finding-A - 'EXAMPLE\\Domain Users'").count(), 0);
    assert.match(await summary.innerText(), /Vulnerable\s+None/);

    await page.goto(`${base}/ca?view=authorities`);
    await rows.first().waitFor();
    assert.equal(await page.locator('#grid-count').textContent(), '3 authorities');
    assert.equal(await page.locator('#ca-authority').count(), 0);
    assert.match(await rows.filter({ hasText: 'CA-One' }).innerText(), /ca-one\.example\.test\s+CN=CA-One, DC=example, DC=test\s+2/);
    assert.equal(requests.filter(({ path }) => path.endsWith('/get/domainca')).some(({ data }) => data.check_all), false);
    await page.getByRole('button', { name: 'Check web enrollment' }).click();
    await page.waitForFunction(() => !document.querySelector('#ca-web').disabled);
    assert.deepEqual(requests.filter(({ path }) => path.endsWith('/get/domainca')).at(-1).data, { no_cache: true, check_all: true });
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('#grid-message').textContent);
    await page.locator('#grid-fields').click();
    await page.getByRole('checkbox', { name: /WebEnrollment/ }).check();
    await page.getByRole('button', { name: 'Done', exact: true }).click();
    await page.locator('th[data-key="web"]').waitFor();
    const web = async (name) => rows.filter({ hasText: name }).locator('td').last().innerText();
    assert.equal(await web('CA-One'), 'http://ca-one.example.test/certsrv');
    assert.equal(await web('CA-Two'), 'No endpoint found: host unreachable or /certsrv missing');
    assert.equal(await web('CA-Three'), 'Not checked: the CA has no host name');
    await rows.filter({ hasText: 'CA-Two' }).click();
    await page.getByRole('tab', { name: 'Templates', exact: true }).click();
    await page.locator('#object-panel').getByText('No endpoint found: host unreachable or /certsrv missing').waitFor();
    await page.getByRole('button', { name: 'Show templates' }).click();
    await page.waitForURL(/view=templates&authority=CA-Two/);
    await page.waitForFunction(() => document.querySelector('#grid-count').textContent === '1 template');
    assert.equal(await page.locator('#ca-authority').inputValue(), 'CA-Two');
    await page.goto(`${base}/ca?view=templates&authority=CA-Three`);
    await page.getByText('No templates found', { exact: true }).waitFor();
    assert.equal(await page.locator('#ca-authority').inputValue(), 'CA-Three');
    assert.equal(new URL(page.url()).searchParams.get('authority'), 'CA-Three');

    for (const colorScheme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme });
      await page.setViewportSize({ width: 390, height: 844 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    }
    assert.deepEqual(errors, []);
    console.log('PASS: Summary rerenders on refresh, CA without templates keeps selection, explicit web enrollment states, template request with resolved SIDs, columns, multi-CA publishing, CA/Not published/findings filters without refetch, URL state, Summary tab, authorities view, explicit web enrollment check kept across refresh, Show templates link, mobile themes.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
