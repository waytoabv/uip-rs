import { chromium } from 'playwright';
const browser = await chromium.launch({ channel: 'chrome' });

async function shoot(url, theme, out, key) {
  const ctx = await browser.newContext({ viewport: { width: 1680, height: 1050 } });
  await ctx.addInitScript((t) => {
    // Beide Apps lesen ihr Theme beim Start aus localStorage.
    localStorage.setItem('ui_theme', t);      // Fork
    localStorage.setItem('uip-theme', t);     // uip-rs
    document.documentElement.setAttribute('data-theme', t);
  }, theme);
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(e.message));
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.waitForTimeout(3500);
    await page.screenshot({ path: `${out}/${key}-${theme}.png` });
    console.log(`${key}-${theme}: ok${errs.length ? ' | errors: ' + errs.slice(0,2).join(' / ') : ''}`);
  } catch (e) {
    console.log(`${key}-${theme}: FAIL ${e.message.split('\n')[0]}`);
  }
  await ctx.close();
}

for (const theme of ['dark', 'light']) {
  await shoot('http://localhost:5199', theme, '/tmp/cmp', 'fork');
  await shoot('http://localhost:8080', theme, '/tmp/cmp', 'ours');
}
await browser.close();
