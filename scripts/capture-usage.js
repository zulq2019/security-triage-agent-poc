// Screenshots of the Usage tab. Usage: NODE_PATH=/workspace/sec-agent-mockup/node_modules node scripts/capture-usage.js <name> [range] [hideSynthetic] [drill]
const { chromium } = require('playwright-core');
const [name = 'usage', range = '30d', hide = '0', drill = '0'] = process.argv.slice(2);
(async () => {
  const b = await chromium.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  const p = await (await b.newContext({ viewport: { width: 1480, height: 920 }, timezoneId: 'Asia/Kolkata' })).newPage();
  p.on('pageerror', e => console.error('pageerror', e.message));
  await p.goto('http://127.0.0.1:8795/?tab=usage');
  await p.waitForTimeout(1500);
  await p.click(`#uRange button[data-r="${range}"]`); await p.waitForTimeout(1200);
  if (hide === '1' && await p.isVisible('#uSynSw')) { await p.click('#uSynSw'); await p.waitForTimeout(1200); }
  await p.screenshot({ path: `shots/${name}.png` });
  await p.evaluate(() => document.querySelector('#v-usage').scrollTo(0, 99999)); await p.waitForTimeout(400);
  await p.screenshot({ path: `shots/${name}-lower.png` });
  if (drill === '1') { await p.click('#uCalls .runlink'); await p.waitForTimeout(1200); await p.screenshot({ path: `shots/${name}-drilldown.png` }); }
  await b.close();
})();
