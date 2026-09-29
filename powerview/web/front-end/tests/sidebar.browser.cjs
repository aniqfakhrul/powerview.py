const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('**/api/**', (route) => route.fulfill({ json: route.request().url().endsWith('/connectioninfo') ? { status: 'OK' } : [] }));
    await page.goto(`${base}/users`);
    const sidebar = page.getByRole('complementary', { name: 'Workspace sidebar' });
    const nav = page.getByRole('navigation', { name: 'Main navigation' });
    const body = page.locator('.workspace__body');
    const width = (value) => page.waitForFunction((expected) => Math.abs(document.querySelector('.sidebar').getBoundingClientRect().width - expected) < 1, value);
    await width(48);
    assert.equal(await nav.locator('a > svg').count(), 10);
    assert.equal(await nav.getByRole('link', { name: 'Users', exact: true }).getAttribute('aria-current'), 'page');
    const before = await body.boundingBox();
    await sidebar.hover();
    await width(208);
    assert.deepEqual(await body.boundingBox(), before);
    assert.ok(await nav.getByRole('link', { name: 'Group policies', exact: true }).locator('span').evaluate((node) => Number(getComputedStyle(node).opacity) > 0.99));
    if (process.env.SIDEBAR_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SIDEBAR_SCREENSHOT_DIR}/desktop-expanded.png` });
    await page.mouse.move(600, 400);
    await width(48);
    await nav.getByRole('link', { name: 'Groups', exact: true }).focus();
    await width(208);
    await page.keyboard.press('Enter');
    await page.waitForURL('**/groups');
    await width(48);
    await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
    assert.equal(await sidebar.evaluate((node) => getComputedStyle(node).transitionDuration), '0s');
    if (process.env.SIDEBAR_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SIDEBAR_SCREENSHOT_DIR}/desktop-collapsed-dark.png` });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(Math.round((await sidebar.boundingBox()).width), 390);
    assert.equal(await nav.getByRole('link', { name: 'Users', exact: true }).locator('span').evaluate((node) => getComputedStyle(node).opacity), '1');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (process.env.SIDEBAR_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SIDEBAR_SCREENSHOT_DIR}/mobile-dark.png` });
    assert.deepEqual(errors, []);
    const touch = await browser.newPage({ viewport: { width: 1280, height: 900 }, hasTouch: true });
    await touch.route('**/api/**', (route) => route.fulfill({ json: [] }));
    await touch.goto(`${base}/users`);
    assert.equal(Math.round((await touch.locator('.sidebar').boundingBox()).width), 208);
    console.log('PASS: sidebar icons, hover and keyboard expansion, stable content layout, navigation, reduced motion, mobile overflow and touch fallback.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
