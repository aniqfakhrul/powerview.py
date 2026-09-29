const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    await context.route('**/api/**', (route) => route.fulfill({ json: route.request().url().endsWith('/connectioninfo') ? { status: 'OK' } : [] }));
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(`${base}/users`);
    const sidebar = page.getByRole('complementary', { name: 'Workspace sidebar' });
    const nav = page.getByRole('navigation', { name: 'Main navigation' });
    const toggle = page.locator('#sidebar-toggle');
    const body = page.locator('.workspace__body');
    const width = (value) => page.waitForFunction((expected) => Math.abs(document.querySelector('.sidebar').getBoundingClientRect().width - expected) < 1, value);
    const labelShown = (name) => nav.getByRole('link', { name, exact: true }).locator('span').evaluate((node) => Number(getComputedStyle(node).opacity) > 0.99);

    await width(208);
    assert.equal(await nav.locator('a > svg').count(), 10);
    assert.equal(await nav.getByRole('link', { name: 'Users', exact: true }).getAttribute('aria-current'), 'page');
    assert.equal(await labelShown('Group policies'), true);
    assert.equal(Math.round((await body.boundingBox()).x), 208);
    assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
    assert.equal(await toggle.getAttribute('aria-label'), 'Collapse sidebar');
    assert.equal(await page.evaluate(() => new Set([...document.querySelectorAll('symbol')].map((node) => node.id)).size === document.querySelectorAll('symbol').length), true);
    if (process.env.SIDEBAR_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SIDEBAR_SCREENSHOT_DIR}/desktop-expanded.png` });

    await toggle.click();
    await width(48);
    assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
    assert.equal(await toggle.getAttribute('aria-label'), 'Expand sidebar');
    assert.equal(Math.round((await body.boundingBox()).x), 48);
    await page.waitForTimeout(300);
    assert.equal(Math.round((await sidebar.boundingBox()).width), 48);
    await page.mouse.move(700, 400);
    const before = await body.boundingBox();
    await sidebar.hover();
    assert.equal(await sidebar.evaluate((node) => getComputedStyle(node).transitionDelay), '0.15s');
    await width(208);
    assert.deepEqual(await body.boundingBox(), before);
    assert.equal(await labelShown('Group policies'), true);
    await page.mouse.move(700, 400);
    await width(48);

    await page.reload();
    assert.equal(await page.evaluate(() => document.documentElement.dataset.sidebar), 'collapsed');
    assert.equal(Math.round((await sidebar.boundingBox()).width), 48);
    while (!(await page.evaluate(() => Boolean(document.activeElement.closest('.sidebar'))))) await page.keyboard.press('Tab');
    await width(208);
    await nav.getByRole('link', { name: 'Groups', exact: true }).focus();
    await page.keyboard.press('Enter');
    await page.waitForURL('**/groups');
    await width(48);
    await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
    assert.equal(await sidebar.evaluate((node) => getComputedStyle(node).transitionDuration), '0s');
    if (process.env.SIDEBAR_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SIDEBAR_SCREENSHOT_DIR}/desktop-collapsed-dark.png` });
    await toggle.click();
    await width(208);
    assert.equal(await page.evaluate(() => localStorage.getItem('powerview.sidebar')), null);
    assert.equal(await toggle.getAttribute('aria-keyshortcuts'), '[');
    await page.mouse.move(700, 400);
    await page.locator('body').click({ position: { x: 700, y: 400 } });
    await page.keyboard.press('[');
    await width(48);
    await sidebar.hover();
    await width(208);
    await page.mouse.move(700, 400);
    await width(48);
    await page.keyboard.press('[');
    await width(208);
    await page.locator('#grid-filter').evaluate((node) => { node.disabled = false; node.focus(); });
    await page.keyboard.press('[');
    assert.equal(await page.locator('#grid-filter').inputValue(), '[');
    assert.equal(Math.round((await sidebar.boundingBox()).width), 208);

    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(Math.round((await sidebar.boundingBox()).width), 390);
    assert.equal(await toggle.isVisible(), false);
    assert.equal(await nav.getByRole('link', { name: 'Users', exact: true }).locator('span').evaluate((node) => getComputedStyle(node).opacity), '1');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (process.env.SIDEBAR_SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SIDEBAR_SCREENSHOT_DIR}/mobile-dark.png` });
    assert.deepEqual(errors, []);

    const touch = await browser.newPage({ viewport: { width: 1280, height: 900 }, hasTouch: true });
    await touch.route('**/api/**', (route) => route.fulfill({ json: [] }));
    await touch.goto(`${base}/users`);
    assert.equal(Math.round((await touch.locator('.sidebar').boundingBox()).width), 208);
    await touch.locator('#sidebar-toggle').tap();
    await touch.waitForFunction(() => Math.abs(document.querySelector('.sidebar').getBoundingClientRect().width - 48) < 1);
    console.log('PASS: sidebar expanded by default, persistent collapse toggle, delayed hover peek without reopening after collapse, keyboard peek, [ shortcut outside text fields, unique icons, navigation, reduced motion, mobile and touch.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
