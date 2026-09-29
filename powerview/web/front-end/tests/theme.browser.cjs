const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'dark' });
    await context.route('**/api/**', (route) => route.fulfill({ json: [] }));
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(`${base}/users`);
    const group = page.getByRole('radiogroup', { name: 'Color theme' });
    const option = (name) => group.getByRole('radio', { name: `${name} theme`, exact: true });
    const checked = () => group.locator('[aria-checked="true"]').getAttribute('data-theme-option');
    const color = () => page.locator('body').evaluate((node) => getComputedStyle(node).color);

    assert.equal(await group.getByRole('radio').count(), 3);
    assert.equal(await checked(), 'system');
    assert.equal(await page.locator('.sidebar__footer').evaluate((node) => getComputedStyle(node).borderTopStyle), 'none');
    const dark = await color();
    await page.emulateMedia({ colorScheme: 'light' });
    const light = await color();
    assert.notEqual(light, dark);
    await option('Dark').click();
    assert.equal(await color(), dark);
    await page.reload();
    assert.equal(await checked(), 'dark');
    assert.equal(await color(), dark);

    const other = await context.newPage();
    await other.goto(`${base}/groups`);
    await option('Light').click();
    await other.waitForFunction(() => document.documentElement.dataset.theme === 'light');
    assert.equal(await other.locator('[data-theme-option="light"]').getAttribute('aria-checked'), 'true');
    await page.emulateMedia({ colorScheme: 'dark' });
    assert.equal(await color(), light);

    await option('Light').focus();
    await page.keyboard.press('ArrowRight');
    assert.equal(await checked(), 'dark');
    assert.equal(await page.evaluate(() => document.activeElement.dataset.themeOption), 'dark');
    await page.keyboard.press('ArrowRight');
    assert.equal(await checked(), 'system');
    assert.deepEqual(await group.getByRole('radio').evaluateAll((nodes) => nodes.map((node) => node.tabIndex)), [0, -1, -1]);
    assert.equal(await color(), dark);
    assert.equal(await page.evaluate(() => localStorage.getItem('powerview.theme')), null);
    if (process.env.THEME_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.THEME_SCREENSHOT_DIR}/desktop-dark.png` });

    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await group.isVisible(), true);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (process.env.THEME_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.THEME_SCREENSHOT_DIR}/mobile-dark.png` });
    await page.addInitScript(() => { Object.defineProperty(window, 'localStorage', { get() { throw new Error('Storage unavailable'); } }); });
    await page.reload();
    await option('Light').click();
    assert.equal(await color(), light);
    assert.deepEqual(errors, []);
    console.log('PASS: three-way theme switch, system default, explicit overrides, persistence, cross-tab sync, arrow-key selection, no footer separator, mobile layout and unavailable storage.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
