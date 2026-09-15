// Vollbild-Aufnahmen aller Ansichten in beiden Themes — auch der Teil
// unterhalb der Falz, weil Diagramme dort sitzen.
import { chromium } from 'playwright';
const OUT = '/tmp/audit';
const browser = await chromium.launch({ channel: 'chrome' });

for (const theme of ['dark', 'light']) {
  const ctx = await browser.newContext({ viewport: { width: 1680, height: 1050 } });
  await ctx.addInitScript((t) => localStorage.setItem('uip-theme', t), theme);
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text()); });

  await page.goto('http://localhost:8080', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `${OUT}/logs-${theme}.png`, fullPage: false });

  await page.getByRole('button', { name: 'Dashboard', exact: true }).click();
  await page.waitForTimeout(3000);
  await page.screenshot({ path: `${OUT}/dash-${theme}.png`, fullPage: true });

  await page.getByRole('button', { name: 'Threat Map', exact: true }).click();
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `${OUT}/map-${theme}.png`, fullPage: true });

  await page.getByRole('button', { name: 'Flow View', exact: true }).click();
  await page.waitForTimeout(2000);
  await page.getByRole('button', { name: 'Zone Matrix', exact: true }).click();
  await page.waitForTimeout(2000);
  await page.screenshot({ path: `${OUT}/zones-${theme}.png`, fullPage: true });

  console.log(`${theme}: ${errs.length ? 'ERRORS ' + errs.slice(0, 2).join(' | ') : 'ok'}`);
  await ctx.close();
}
await browser.close();
