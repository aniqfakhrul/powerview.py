/** Run against a local shell preview. Every API call is intercepted with test fixtures. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const rootDN = 'DC=example,DC=test';
const group = (name, groupType, member = []) => ({ dn: `CN=${name},CN=Users,${rootDN}`, attributes: {
  name, sAMAccountName: name, groupType, description: `${name} group`, member, whenCreated: 'Thu, 14 Aug 2025 15:40:15 GMT',
} });
let groups = [
  group('Admins', -2147483646, [`CN=Alpha,CN=Users,${rootDN}`, `CN=Bravo,CN=Users,${rootDN}`]),
  group('Local Ops', -2147483644, `CN=Alpha,CN=Users,${rootDN}`),
  group('Newsletter', 8),
];
groups[2].attributes['member;range=0-1499'] = Array.from({ length: 1500 }, (_, index) => `CN=Member ${index},CN=Users,${rootDN}`);

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = []; const listRequests = []; const creates = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = route.request().postDataJSON();
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: rootDN } });
    if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [rootDN] } } });
    if (path.endsWith('/schema/attributes')) return route.fulfill({ json: { available: false, class: 'group', attributes: [] } });
    if (path.endsWith('/get/domaingroup')) {
      listRequests.push(data);
      if (data.args?.memberidentity === 'nobody') return route.fulfill({ json: [] });
      return route.fulfill({ json: data.search_scope === 'BASE' ? groups.filter((item) => item.dn === data.searchbase) : groups });
    }
    if (path.endsWith('/add/domaingroup')) {
      creates.push(data);
      groups = [...groups, group(data.groupname, -2147483646)];
      return route.fulfill({ json: true });
    }
    return route.fulfill({ json: [] });
  });
  const rows = page.locator('#grid-body tr[data-dn]');

  await page.goto(`${base}/groups`);
  await rows.first().waitFor();
  assert.equal(await page.locator('#grid-count').textContent(), '3 groups');
  assert.equal(listRequests[0].raw, true);
  assert.deepEqual(await page.locator('#grid-head .column-sort__label').allTextContents(), ['name', 'sAMAccountName', 'Type', 'description', 'member (count)', 'whenCreated']);
  const cells = async (name) => (await rows.filter({ hasText: name }).locator('td').allTextContents()).slice(3, 6);
  assert.deepEqual(await cells('Admins'), ['Global security', 'Admins group', '2']);
  assert.deepEqual(await cells('Local Ops'), ['Domain local security', 'Local Ops group', '1']);
  assert.deepEqual(await cells('Newsletter'), ['Universal distribution', 'Newsletter group', '1500+']);
  assert.match(await rows.filter({ hasText: 'Newsletter' }).locator('.cell-partial').getAttribute('title'), /first 1500 values/);
  await page.getByRole('button', { name: 'member (count)', exact: true }).click();
  await page.getByRole('button', { name: 'member (count)', exact: true }).click();
  assert.equal(await rows.first().getAttribute('data-dn'), `CN=Newsletter,CN=Users,${rootDN}`);

  await page.getByRole('button', { name: /^Filters/ }).click();
  await page.locator('#search-menu').getByLabel('Has member', { exact: true }).fill('Alpha');
  const searched = page.waitForResponse((response) => response.url().endsWith('/get/domaingroup'));
  await page.locator('#search-menu').getByRole('button', { name: 'Apply' }).click();
  await searched;
  assert.deepEqual(listRequests.at(-1).args, { memberidentity: 'Alpha' });
  await page.getByRole('button', { name: /^Filters/ }).click();
  await page.locator('#search-menu').getByLabel('Has member', { exact: true }).fill('nobody');
  const none = page.waitForResponse((response) => response.url().endsWith('/get/domaingroup'));
  await page.locator('#search-menu').getByRole('button', { name: 'Apply' }).click();
  await none;
  await page.getByRole('heading', { name: 'No groups found' }).waitFor();
  assert.equal(await page.getByRole('heading', { name: /Cannot load/ }).count(), 0);
  await page.getByRole('button', { name: /^Filters/ }).click();
  assert.equal(await page.locator('#search-menu').getByLabel('Identity', { exact: true }).getAttribute('placeholder'), 'Name or distinguished name');
  await page.locator('#search-menu').getByRole('button', { name: 'Clear' }).click();
  const cleared = page.waitForResponse((response) => response.url().endsWith('/get/domaingroup'));
  await page.locator('#search-menu').getByRole('button', { name: 'Apply' }).click();
  await cleared;

  await page.getByRole('button', { name: 'New group', exact: true }).click();
  const dialog = page.locator('#group-dialog');
  assert.equal(await dialog.getByRole('textbox', { name: 'Container' }).inputValue(), `CN=Users,${rootDN}`);
  assert.equal(await dialog.locator('input[type="password"]').count(), 0);
  await dialog.getByRole('textbox', { name: 'Name' }).fill('Bad,Name');
  await dialog.getByRole('button', { name: 'Create' }).click();
  await page.waitForFunction(() => !document.querySelector('#group-error').hidden);
  assert.equal(creates.length, 0);
  await dialog.getByRole('textbox', { name: 'Name' }).fill('Build Team');
  await dialog.getByRole('button', { name: 'Create' }).click();
  await page.waitForFunction(() => !document.querySelector('#group-dialog').open);
  assert.deepEqual(creates, [{ groupname: 'Build Team', basedn: `CN=Users,${rootDN}` }]);
  await page.locator('.toast--success', { hasText: 'Created Build Team' }).waitFor();
  await page.waitForFunction(() => document.querySelectorAll('#grid-body tr[data-dn]').length === 1);
  assert.equal(listRequests.at(-1).search_scope, 'BASE');
  assert.equal(await page.locator('#grid-filter').inputValue(), 'Build Team');

  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  assert.deepEqual(errors, []);
  console.log('PASS: group endpoint and columns, groupType scope/security decoding, member counts incl. ranged partial counts, unknown member shows empty results, Identity hint, Has member search, New group validation and single-object read, mobile overflow.');
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
