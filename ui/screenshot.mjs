// Schießt einen Satz Screenshots aller Ansichten gegen eine laufende Instanz.
// Nutzt das installierte Chrome (channel: 'chrome'), weil Playwrights eigener
// Chromium-Download hier in einen Timeout läuft.
//
//   node screenshot.mjs http://localhost:8080 /tmp/uipshots
//
// Gedacht zum Vergleich mit der Vorlage — Aussehen lässt sich nicht sinnvoll
// per Zusicherung testen, aber man kann es ansehen.
import { chromium } from 'playwright';

const BASE = process.argv[2] || 'http://localhost:8080';
const OUT = process.argv[3] || '/tmp/uipshots';
const views = [
  ['Log Stream', 'logs'],
  ['Flow View', 'flows'],
  ['Threat Map', 'map'],
  ['Dashboard', 'dashboard'],
];

const browser = await chromium.launch({ channel: 'chrome' });
const page = await browser.newPage({ viewportSize: { width: 1680, height: 1050 } });

const errors = [];
page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
page.on('console', (m) => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });

await page.goto(BASE, { waitUntil: 'networkidle' });
await page.waitForTimeout(1500);

for (const [label, id] of views) {
  try {
    const tab = page.getByRole('button', { name: label, exact: true });
    if (await tab.count()) { await tab.first().click(); await page.waitForTimeout(2000); }
  } catch (e) { errors.push(`tab ${label}: ${e.message}`); }
  await page.screenshot({ path: `${OUT}/${id}.png`, fullPage: false });
  console.log(`shot ${id}`);
}

console.log(errors.length ? 'ERRORS:\n' + errors.join('\n') : 'no console errors');
await browser.close();
