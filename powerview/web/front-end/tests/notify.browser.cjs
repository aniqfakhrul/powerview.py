/** Run against a local shell preview. Every API call is intercepted. */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const base = process.env.EXPLORER_URL || 'http://127.0.0.1:5011';

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 700 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/**', (route) => route.fulfill({ json: [] }));
  await page.goto(`${base}/dashboard`);
  const show = (text, tone = 'success') => page.evaluate(async ([message, kind]) => {
    const { notify } = await import('/static/js/components/notify.js');
    notify[kind](message);
  }, [text, tone]);
  const closeButton = (text) => page.locator('.toast', { hasText: text }).getByRole('button', { name: 'Dismiss notification' });
  const active = () => page.evaluate(() => document.activeElement.closest('.toast')?.textContent ?? document.activeElement.id ?? document.activeElement.tagName);

  await show('Stays while focused');
  await closeButton('Stays while focused').focus();
  await closeButton('Stays while focused').hover();
  await page.mouse.move(10, 10);
  await page.waitForTimeout(4600);
  assert.equal(await closeButton('Stays while focused').count(), 1);
  await page.locator('#main-content').focus();
  await page.waitForTimeout(4600);
  assert.equal(await closeButton('Stays while focused').count(), 0);

  await show('Stays while hovered');
  await page.locator('.toast', { hasText: 'Stays while hovered' }).hover();
  await page.waitForTimeout(4600);
  assert.equal(await closeButton('Stays while hovered').count(), 1);
  await page.mouse.move(10, 10);
  await page.waitForTimeout(4600);
  assert.equal(await closeButton('Stays while hovered').count(), 0);

  const origin = page.getByRole('link', { name: 'Users', exact: true });
  await origin.focus();
  await show('Only toast', 'error');
  await closeButton('Only toast').focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Users');

  await show('Older', 'error');
  await show('Newer', 'error');
  await closeButton('Newer').focus();
  await page.keyboard.press('Enter');
  assert.match(await active(), /Older/);
  await page.keyboard.press('Enter');

  for (const text of ['First', 'Second', 'Third']) await show(text, 'warn');
  await closeButton('First').focus();
  await show('Fourth', 'warn');
  assert.equal(await closeButton('First').count(), 0);
  await page.locator('.toast', { hasText: 'First' }).waitFor({ state: 'detached' });
  assert.match(await active(), /Second/);
  assert.notEqual(await page.evaluate(() => document.activeElement.tagName), 'BODY');

  assert.deepEqual(errors, []);
  console.log('PASS: toasts stay while focused or hovered and dismiss after both end; dismissing restores focus to the origin or a neighbouring toast; eviction keeps focus inside notifications.');
  await browser.close();
})().catch((error) => { console.error(error); process.exit(1); });
