// Starts a real run from the dashboard ("Run on PR #n") and captures screenshots mid-run and at the end.
// Usage: NODE_PATH=/workspace/sec-agent-mockup/node_modules node scripts/capture-run.js [prNumber] [prefix]
const { chromium } = require('playwright-core');
const pr = process.argv[2] || '1', prefix = process.argv[3] || 'run';
const out = n => `shots/${prefix}-${n}.png`;
(async () => {
  const b = await chromium.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  const p = await (await b.newContext({ viewport: { width: 1480, height: 920 }, timezoneId: 'Asia/Kolkata' })).newPage();
  await p.goto('http://127.0.0.1:8795/');
  await p.fill('#prNum', pr);
  await p.click('#runBtn');
  const t0 = Date.now();
  const state = () => p.evaluate(() => { const s = __state(); return { agents: Object.fromEntries(Object.entries(s.agents).map(([k, v]) => [k, v.s])), status: s.run && s.run.status, prs: Object.keys(s.prs).length }; });
  const shots = [
    ['1-triage', s => s.agents.triage === 'running' && document],
  ];
  const taken = new Set();
  const want = {
    '1-triage': s => s.agents.triage === 'running',
    '2-fixers': s => ['lib', 'secrets', 'unsafe', 'binary'].filter(a => s.agents[a] === 'running').length >= 2,
    '3-retry': s => Object.values(s.agents).includes('retry'),
    '4-prs': s => s.prs > 0 && s.status === 'running',
    '5-end': s => s.status && s.status !== 'running',
  };
  while (true) {
    const s = await state();
    for (const [name, cond] of Object.entries(want))
      if (!taken.has(name) && cond(s)) {
        if (name === '1-triage') await p.waitForTimeout(25000);   // let a few triage entries land
        await p.screenshot({ path: out(name) }); taken.add(name);
        console.log(`${name} at +${((Date.now() - t0) / 1000).toFixed(0)}s`, JSON.stringify(s));
      }
    if (taken.has('5-end') || Date.now() - t0 > 40 * 60 * 1000) break;
    await p.waitForTimeout(1500);
  }
  await p.waitForTimeout(1500);
  await p.screenshot({ path: out('5-end') });
  await p.click('.tab[data-v="findings"]'); await p.waitForTimeout(1500); await p.screenshot({ path: out('6-findings-tab') });
  await p.click('.tab[data-v="controls"]'); await p.waitForTimeout(1000); await p.screenshot({ path: out('7-controls-tab') });
  console.log('total', ((Date.now() - t0) / 1000).toFixed(0), 's');
  await b.close();
})();
