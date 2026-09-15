import { chromium } from 'playwright';
const browser = await chromium.launch({ channel: 'chrome' });
for (const theme of ['light','dark']) {
  const ctx = await browser.newContext({ viewport: { width: 1680, height: 1050 } });
  await ctx.addInitScript((t) => localStorage.setItem('uip-theme', t), theme);
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(e.message));
  await page.goto('http://localhost:8080', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2500);
  await page.getByRole('button', { name: 'Flow View', exact: true }).click();
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `/tmp/cmp/flow-${theme}.png` });
  await page.getByRole('button', { name: 'IP Pairs', exact: true }).click();
  await page.waitForTimeout(2000);
  await page.screenshot({ path: `/tmp/cmp/pairs-${theme}.png` });
  console.log(`${theme}: ${errs.length ? 'ERRORS ' + errs[0] : 'ok'}`);
  await ctx.close();
}
await browser.close();
