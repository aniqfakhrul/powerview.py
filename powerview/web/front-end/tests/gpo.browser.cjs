/** Local shell preview only. All directory requests are intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';
const root = 'DC=example,DC=test';
const policies = `CN=Policies,CN=System,${root}`;
const id = (digit) => `{${digit.repeat(8)}-0000-0000-0000-000000000000}`;
const link = (guid, flags) => `[LDAP://cn=${guid},${policies};${flags}]`;
const policy = (digit, displayName, attributes = {}) => ({ dn: `CN=${id(digit)},${policies}`, attributes: { name: id(digit), displayName, flags: 0, versionNumber: 0, ...attributes } });
let policiesList = [
  policy('1', 'Workstation Baseline', { versionNumber: (3 << 16) + 7 }),
  policy('2', 'Legacy Settings', { flags: 3 }),
];
let targets = { root: { dn: root, attributes: { name: 'example', gPLink: link(id('1'), 0) } }, ous: [
  { dn: `OU=Staff,${root}`, attributes: { name: 'Staff', gPLink: link(id('1'), 2) } },
  { dn: `OU=Lab,${root}`, attributes: { name: 'Lab', gPLink: [] } },
] };
const settings = { attributes: { name: id('1'), machineConfig: { Security: { 'System Access': { MinimumPasswordLength: '14' }, Unicode: { Unicode: 'yes' } } }, userConfig: {} } };

function setLink(dn, value) {
  if (dn === root) targets.root.attributes.gPLink = value;
  else targets.ous = targets.ous.map((item) => (item.dn === dn ? { ...item, attributes: { ...item.attributes, gPLink: value } } : item));
}
const linkOf = (dn) => (dn === root ? targets.root : targets.ous.find((item) => item.dn === dn)).attributes.gPLink;

async function open(browser, { linkFails = false } = {}) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 800 } });
  const state = { errors: [], writes: [], settingsReads: 0 };
  page.on('pageerror', (error) => state.errors.push(error.message));
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = route.request().postDataJSON();
    if (path.endsWith('/get/domaininfo')) return route.fulfill({ json: { root_dn: root } });
    if (path.endsWith('/connectioninfo')) return route.fulfill({ json: { status: 'OK' } });
    if (path.endsWith('/server/info')) return route.fulfill({ json: { raw: { namingContexts: [root] } } });
    if (path.endsWith('/schema/attributes')) return route.fulfill({ json: { available: false } });
    if (path.endsWith('/get/domainou')) return route.fulfill({ json: targets.ous });
    if (path.endsWith('/get/domaingposettings')) { state.settingsReads += 1; return route.fulfill({ json: [settings] }); }
    if (path.endsWith('/get/domaingpo')) {
      const identity = data.args?.identity;
      return route.fulfill({ json: identity ? policiesList.filter((item) => item.attributes.displayName === identity) : policiesList });
    }
    if (path.endsWith('/get/domainobject')) {
      if (data.searchbase === root) return route.fulfill({ json: [targets.root] });
      return route.fulfill({ json: policiesList.filter((item) => item.dn === data.searchbase).map((item) => ({ ...item, attributes: { ...item.attributes, objectClass: ['top', 'container', 'groupPolicyContainer'] } })) });
    }
    if (/domainobject(acl|owner)$/.test(path)) return route.fulfill({ json: [] });
    if (path.endsWith('/add/gplink')) {
      state.writes.push({ path: 'add/gplink', data });
      if (linkFails) return route.fulfill({ status: 400, json: { error: 'Insufficient access rights' } });
      const flags = (data.enforced === 'Yes' ? 2 : 0) + (data.link_enabled === 'No' ? 1 : 0);
      setLink(data.targetidentity, [linkOf(data.targetidentity)].flat().join('') + link(data.guid, flags));
      return route.fulfill({ json: true });
    }
    if (path.endsWith('/remove/gplink')) {
      state.writes.push({ path: 'remove/gplink', data });
      setLink(data.targetidentity, [linkOf(data.targetidentity)].flat().join('').replace(link(data.guid, 0), '').replace(link(data.guid, 2), ''));
      return route.fulfill({ json: true });
    }
    if (path.endsWith('/add/domaingpo')) {
      state.writes.push({ path: 'add/domaingpo', data });
      policiesList = [...policiesList, policy('3', data.identity)];
      return route.fulfill({ json: true });
    }
    throw new Error(`Unexpected API request: ${path}`);
  });
  await page.goto(`${base}/gpo`);
  await page.locator('#grid-body tr[data-dn]').first().waitFor();
  return { page, state };
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const { page, state } = await open(browser);
    const rows = page.locator('#grid-body tr[data-dn]');
    const row = (digit) => page.locator(`#grid-body tr[data-dn="CN=${id(digit)},${policies}"]`);
    assert.equal(await page.locator('#grid-count').textContent(), '2 group policies');
    assert.deepEqual(await page.locator('#grid-head .column-sort__label').allTextContents(), ['displayName', 'Status', 'Linked to', 'User version', 'Computer version', 'whenChanged']);
    await page.waitForFunction(() => document.querySelector('#grid-body').innerText.includes('example (domain)'));
    assert.match(await row('1').innerText(), /Workstation Baseline\s+All settings enabled\s+example \(domain\); Staff \(enforced\)\s+3\s+7/);
    assert.match(await row('2').innerText(), /Legacy Settings\s+All settings disabled/);

    await row('1').click();
    await page.getByRole('tab', { name: 'Policy', exact: true }).click();
    const panel = page.locator('#object-panel .properties:visible');
    await panel.getByText('14', { exact: true }).waitFor();
    assert.match(await panel.innerText(), /Computer › Security › System Access › MinimumPasswordLength\s+14/);
    assert.doesNotMatch(await panel.innerText(), /Unicode/);
    assert.match(await page.locator('[data-panel-title]').innerText(), /Workstation Baseline\s+Group policy/);
    assert.equal(await page.getByRole('button', { name: 'Delete object' }).count(), 0);
    await row('2').click();
    await row('1').click();
    await page.getByRole('tab', { name: 'Policy', exact: true }).click();
    await panel.getByText('14', { exact: true }).waitFor();
    assert.equal(state.settingsReads, 2);

    await page.getByRole('button', { name: 'Manage links' }).click();
    const dialog = page.locator('#links-dialog');
    await dialog.waitFor();
    assert.deepEqual(await dialog.locator('#links-list .links-list__name').allTextContents(), ['example (domain)', 'Staff']);
    assert.deepEqual(await dialog.locator('#links-target option').allTextContents(), [`Lab — OU=Lab,${root}`]);
    await dialog.locator('#links-enforced').check();
    await dialog.getByRole('button', { name: 'Add link' }).click();
    await page.locator('.toast--success', { hasText: 'Linked Workstation Baseline to Lab' }).waitFor();
    assert.deepEqual(state.writes.at(-1), { path: 'add/gplink', data: { guid: id('1'), targetidentity: `OU=Lab,${root}`, link_enabled: 'Yes', enforced: 'Yes' } });
    await dialog.locator('#links-list li', { hasText: 'Lab' }).waitFor();
    assert.equal(await dialog.getByRole('button', { name: 'Add link' }).isDisabled(), true);
    await dialog.locator('#links-list li', { hasText: 'Staff' }).getByRole('button', { name: 'Unlink' }).click();
    await page.locator('.toast--success', { hasText: 'Unlinked Workstation Baseline from Staff' }).waitFor();
    assert.deepEqual(state.writes.at(-1), { path: 'remove/gplink', data: { guid: id('1'), targetidentity: `OU=Staff,${root}` } });
    await page.waitForFunction(() => !document.querySelector('#links-list').innerText.includes('Staff'));
    await dialog.getByRole('button', { name: 'Close' }).click();
    await page.waitForFunction(() => document.querySelector('#grid-body').innerText.includes('Lab (enforced)'));

    await page.getByRole('button', { name: 'New GPO', exact: true }).click();
    const create = page.locator('#gpo-dialog');
    await create.locator('#gpo-name').fill('Kiosk Lockdown');
    await create.locator('#gpo-description').fill('Kiosk devices');
    await create.locator('#gpo-linkto').selectOption(`OU=Staff,${root}`);
    await create.getByRole('button', { name: 'Create' }).click();
    await page.locator('.toast--success', { hasText: 'Created Kiosk Lockdown and linked it' }).waitFor();
    assert.deepEqual(state.writes.find((item) => item.path === 'add/domaingpo').data, { identity: 'Kiosk Lockdown', description: 'Kiosk devices' });
    assert.deepEqual(state.writes.at(-1).data, { guid: id('3'), targetidentity: `OU=Staff,${root}`, link_enabled: 'Yes', enforced: 'No' });
    await row('3').waitFor();
    assert.deepEqual(state.errors, []);
    await page.close();

    // A response from the previous selection must not replace the current panel.
    for (const status of [200, 500]) {
      const switching = await open(browser);
      const current = switching.page;
      let release;
      const held = new Promise((resolve) => { release = resolve; });
      let started;
      const requested = new Promise((resolve) => { started = resolve; });
      await current.route('**/api/get/domaingposettings', async (route) => {
        const first = route.request().postDataJSON().identity === id('1');
        if (first) { started(); await held; }
        await route.fulfill(first && status === 500
          ? { status: 500, json: { error: 'Old policy failed' } }
          : { json: [{ attributes: { machineConfig: { Marker: first ? 'OLD SETTINGS' : 'CURRENT SETTINGS' } } }] });
      });
      await current.locator('#grid-body tr[data-dn]').filter({ hasText: 'Workstation Baseline' }).click();
      await requested;
      await current.getByRole('tab', { name: 'Policy', exact: true }).click();
      await current.locator('#grid-body tr[data-dn]').filter({ hasText: 'Legacy Settings' }).click();
      await current.getByText('CURRENT SETTINGS', { exact: true }).waitFor();
      const completed = current.waitForResponse((response) => response.url().endsWith('/get/domaingposettings') && response.request().postDataJSON().identity === id('1'));
      release();
      await (await completed).finished();
      await current.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      assert.match(await current.locator('#object-panel .properties:visible').innerText(), /CURRENT SETTINGS/);
      assert.deepEqual(switching.state.errors, []);
      await current.close();
    }

    const failing = await open(browser, { linkFails: true });
    await failing.page.locator('#grid-body tr[data-dn]').filter({ hasText: 'Legacy Settings' }).click();
    await failing.page.getByRole('button', { name: 'Manage links' }).click();
    const failedDialog = failing.page.locator('#links-dialog');
    await failedDialog.locator('#links-target').selectOption(`OU=Lab,${root}`);
    await failedDialog.getByRole('button', { name: 'Add link', exact: true }).click();
    await failedDialog.locator('#links-error').waitFor();
    assert.equal(await failedDialog.locator('#links-target').inputValue(), `OU=Lab,${root}`);
    await failedDialog.getByRole('button', { name: 'Add link', exact: true }).click();
    await failing.page.waitForFunction(() => !document.querySelector('#links-form button[type="submit"]').disabled);
    assert.equal(failing.state.writes.at(-1).data.targetidentity, `OU=Lab,${root}`);
    await failedDialog.getByRole('button', { name: 'Close' }).click();
    await failing.page.locator('#panel-close').click();

    await failing.page.getByRole('button', { name: 'New GPO', exact: true }).click();
    await failing.page.locator('#gpo-name').fill('Printer Rollout');
    await failing.page.locator('#gpo-linkto').selectOption(`OU=Lab,${root}`);
    await failing.page.locator('#gpo-form button[type="submit"]').click();
    await failing.page.locator('.toast--warn', { hasText: 'Created Printer Rollout, but it could not be linked. Insufficient access rights' }).waitFor();
    assert.deepEqual(failing.state.errors, []);

    console.log('PASS: late SYSVOL success/error cannot overwrite the selected policy, failed link retries preserve target, GPO columns (status, links with enforced state, user/computer versions), display-name titles, Policy tab with cached SYSVOL settings and boilerplate hidden, no delete, Manage links add/remove with fresh targets, New GPO with description and verified link, link failure reported as partial success.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exit(1); });
