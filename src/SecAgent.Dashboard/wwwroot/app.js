(() => {
const $ = s => document.querySelector(s);
const CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';
const CHEV = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>';
const RETRY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg>';
const X = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg>';
const I = p => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const ICONS = {
  scanners: I('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/><path d="M11 8v6M8 11h6"/>'),
  orch: I('<rect x="9" y="2.5" width="6" height="5" rx="1.2"/><rect x="2.5" y="16.5" width="6" height="5" rx="1.2"/><rect x="15.5" y="16.5" width="6" height="5" rx="1.2"/><path d="M12 7.5V12M5.5 16.5V12h13v4.5"/>'),
  triage: I('<path d="M3 4h18l-7 8.5V19l-4 2v-8.5z"/>'),
  router: I('<path d="M6 3v6a6 6 0 0 0 6 6h6"/><path d="M6 21v-6"/><path d="m15 12 3 3-3 3"/><circle cx="6" cy="3" r="0.6"/>'),
  lib: I('<path d="m21 8-9-5-9 5 9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>'),
  secrets: I('<circle cx="7.5" cy="15.5" r="4.5"/><path d="m11 12 9-9M17 6l3 3M14.5 8.5l2 2"/>'),
  unsafe: I('<path d="m8 7-5 5 5 5M16 7l5 5-5 5M13.5 4l-3 16"/>'),
  binary: I('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8.5 13v4M12 13v4M15.5 13v4"/>'),
  verifier: I('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>'),
  human: I('<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7"/>'),
};
// Agents (ids match the workflow executors). The model chip shows the tier actually used in this run; "no LLM" = deterministic step.
const AGENTS = [
  {id:'scanners', name:'Scanners', model:'tool', color:'#55707a', bg:'#eef2f4'},
  {id:'orch', name:'Orchestrator', model:'tool', color:'#12303a', bg:'#e6edf0'},
  {id:'triage', name:'Triage', model:null, color:'#4f46c8', bg:'#ecebfb'},
  {id:'router', name:'Router', model:'tool', color:'#2463c7', bg:'#e8effb'},
  {id:'lib', name:'Library fixer', model:null, color:'#0f7c7c', bg:'#e2f3f2'},
  {id:'secrets', name:'Secrets fixer', model:null, color:'#a05c00', bg:'#fbf0dc'},
  {id:'unsafe', name:'Unsafe code fixer', model:null, color:'#b8325a', bg:'#fbe9ef'},
  {id:'binary', name:'Binary/Licence fixer', model:null, color:'#7a45c9', bg:'#f2eafc'},
  {id:'verifier', name:'Verifier', model:null, color:'#1a7f4b', bg:'#e6f4ec'},
  {id:'human', name:'Human review', model:'none', color:'#b26a00', bg:'#fdf3e1'},
];
const A = Object.fromEntries(AGENTS.map(a => [a.id, a]));
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const fmtTok = n => { n = Math.round(n || 0); return n >= 1000 ? (n/1000).toFixed(1) + 'k' : String(n); };
const IST = {timeZone:'Asia/Kolkata', hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'};
const clock = ts => new Date(ts).toLocaleTimeString('en-GB', IST);
const mmss = s => { s = Math.max(0, Math.floor(s)); return String(Math.floor(s/60)).padStart(2,'0') + ':' + String(s%60).padStart(2,'0'); };
const toast = m => { const t = $('#toast'); t.textContent = m; t.classList.add('show'); clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.remove('show'), 2600); };

let st, es;
function reset(){
  st = {seq:0, agents:Object.fromEntries(AGENTS.map(a => [a.id, {s:'queued', text:'Queued', tok:0, tier:null}])), run:null, prs:{}, entries:{}, tools:{}, total:0, budget:0, checkpoints:0};
  $('#pipe').innerHTML = AGENTS.map(a => `
   <div class="agent st-queued" id="ag-${a.id}">
     <div class="ico">${ICONS[a.id]}<span class="badge"></span></div>
     <div class="a-body">
       <div class="a-name">${a.name}<span class="chip-m tool" style="${a.model ? '' : 'display:none'}">${a.model === 'tool' ? 'no LLM' : a.model === 'none' ? 'human' : ''}</span><span class="retry-tag" style="display:none">retry</span></div>
       <div class="a-status">Queued</div>
     </div>
     <div class="a-tok zero">${a.model ? '—' : '0'}</div>
   </div>`).join('');
  $('#feed').innerHTML = '<div class="empty" id="empty">Waiting for run to start…</div>';
  ['fix','batch','sup','hum'].forEach(k => { $('#c-' + k).textContent = '0'; $('#s-' + k).style.width = '0'; });
  $('#findMeta').textContent = '0 of 0 triaged';
  $('#prs').innerHTML = '<div class="noprs">No fix PRs yet — fixers haven\'t finished</div>'; $('#prMeta').textContent = '0 open'; $('#tasks').innerHTML = '';
  $('#gMask').textContent = '0 masked'; $('#gInj').classList.remove('hit'); $('#gInjM').textContent = '0 ignored'; $('#gRetry').textContent = '0 used'; $('#gRet').classList.remove('hit'); $('#gMeta').textContent = 'all passing';
  $('#agentsDone').textContent = '0 / 10';
  $('#reviewBtn').style.display = 'none';
}

function setAgent(id, s, text, tokens){
  const a = st.agents[id]; if (!a) return;
  a.s = s; a.text = text; if (tokens != null && tokens > 0) a.tok = tokens;
  const el = $('#ag-' + id);
  el.className = 'agent st-' + s;
  el.querySelector('.badge').innerHTML = s === 'done' ? CHECK : s === 'retry' ? RETRY : (s === 'failed' || s === 'stopped') ? X : '';
  const sEl = el.querySelector('.a-status');
  sEl.className = 'a-status' + (s === 'running' ? ' shimmer' : s === 'retry' ? ' shimmer orange' : '');
  sEl.textContent = s === 'done' ? '✓ ' + text : text;
  if (s === 'retry') el.querySelector('.retry-tag').style.display = '';
  renderTokens();
  $('#agentsDone').textContent = Object.values(st.agents).filter(x => x.s === 'done').length + ' / 10';
  refreshStatusline();
}
function renderTokens(){
  for (const id in st.agents){
    const a = st.agents[id]; if (A[id].model) continue;
    const el = $('#ag-' + id + ' .a-tok'); el.textContent = fmtTok(a.tok); el.classList.toggle('zero', !a.tok);
    const chip = $('#ag-' + id + ' .chip-m');
    if (a.tier){ chip.style.display = ''; chip.className = 'chip-m ' + (a.tier === 'strong' ? 'strong' : 'small'); chip.textContent = a.tier; }
  }
  $('#budgetV').innerHTML = `${fmtTok(st.total)} <small>/ ${fmtTok(st.budget)} tokens</small>`;
  const pct = st.budget ? st.total / st.budget * 100 : 0;
  $('#budgetBar').style.width = Math.min(100, pct) + '%';
  $('#gBudget').textContent = Math.round(pct) + '% used';
}
function refreshStatusline(){
  const sl = $('#statusline'), r = st.run;
  if (r && r.status !== 'running'){
    sl.className = 'statusline done'; $('#glyph').textContent = '◆'; $('#slText').className = 'sl-text';
    $('#slText').textContent = r.status === 'waiting' ? 'Waiting for human review · run paused' : r.status === 'stopped_kill_switch' ? 'Stopped by kill switch' :
      r.status === 'stopped_budget' ? 'Stopped · budget exhausted' : r.status === 'failed' ? 'Run failed · ' + (r.stop_detail || '') : 'Run ' + r.status;
    return;
  }
  sl.className = 'statusline';
  const running = Object.entries(st.agents).filter(([,a]) => a.s === 'running' || a.s === 'retry');
  if (!running.length) return;
  $('#slText').textContent = running.length > 1 ? `${running.length} agents working · ` + running.map(([,a]) => a.text).join(' · ') : running[0][1].text;
  $('#slText').className = 'sl-text shimmer';
}
function entry(d, ts){
  const emp = $('#empty'); if (emp) emp.remove();
  const ag = A[d.agent] || A.orch;
  let e = st.entries[d.id];
  if (!e){
    e = document.createElement('div');
    e.innerHTML = `<div class="ts">${clock(ts)}</div><div class="e-main"><div class="e-head"><span class="achip" style="color:${ag.color};background:${ag.bg}"><i></i>${esc(ag.name)}</span><span class="e-text"></span></div><div class="tools"></div></div>`;
    $('#feed').appendChild(e); st.entries[d.id] = e;
  }
  e.className = 'entry ' + (d.kind || '');
  e.querySelector('.e-text').textContent = d.text;
  if (d.flag) setFlag(e, d.flag);
  if (d.think){
    let th = e.querySelector('.think');
    if (!th){ th = document.createElement('div'); th.className = 'think'; e.querySelector('.e-head').after(th); }
    th.innerHTML = `<span class="think-t">${CHEV}<span>Model reason${d.think_secs ? ` · ${d.think_secs}s` : ''}</span></span><div class="think-b"></div>`;
    th.querySelector('.think-b').textContent = d.think;
    th.querySelector('.think-t').onclick = () => th.classList.toggle('open');
  }
}
function setFlag(e, f){
  let fl = e.querySelector('.flag');
  if (!fl){ fl = document.createElement('span'); e.querySelector('.e-head').appendChild(fl); }
  fl.className = 'flag show ' + esc(f[0]); fl.textContent = f[1];
}
function tool(d){
  const e = st.entries[d.entry]; if (!e) return;
  let ln = st.tools[d.id];
  if (!ln){ ln = document.createElement('div'); ln.className = 'tool'; e.querySelector('.tools').appendChild(ln); st.tools[d.id] = ln; }
  const icon = d.state === 'running' ? '<span class="spin"></span>' : d.state === 'ok' ? CHECK : X;
  ln.innerHTML = `<span class="tst ${d.state === 'fail' ? 'x' : ''}">${icon}</span><span class="tk">tool:</span><span class="tn">${esc(d.name)}</span><span class="ta" title="${esc(d.args)}">${esc(d.args)}</span>` +
    (d.ms != null ? `<span class="td">${d.ms >= 1000 ? (d.ms/1000).toFixed(1) + 's' : d.ms + 'ms'}</span>` : '');
}
function detail(d){
  const e = st.entries[d.entry]; if (!e) return;
  const x = d.detail, box = document.createElement('div'); box.className = 'detail';
  if (x.type === 'code'){
    box.innerHTML = (x.files || []).map(f => `<div class="code"><span class="fn">${esc(f.file)}</span>` +
      f.lines.map(l => `<span class="${esc(l.t)}">${l.t === 'add' ? '+ ' : l.t === 'del' ? '- ' : l.t === 'hunk' ? '@@ ' : '  '}${esc(l.s)}</span>`).join('') +
      (f.more ? `<span class="hunk">… ${f.more} more lines in the PR</span>` : '') + `</div>`).join('');
  } else if (x.type === 'quote'){
    box.innerHTML = `<div class="quote">${esc(x.ref)}<code>${esc(x.code)}</code>${esc(x.text)}</div>`;
  } else if (x.type === 'fail'){
    box.innerHTML = `<div class="failbox"></div>`; box.firstChild.textContent = x.text;
  } else if (x.type === 'pr'){
    box.innerHTML = `<div class="prbox"><a href="${esc(x.url)}" target="_blank" rel="noopener">#${esc(x.num)}</a><span>${esc(x.title)}</span></div>`;
  } else {
    box.innerHTML = `<div class="evid"></div>`; box.firstChild.textContent = x.text;
  }
  e.querySelector('.e-main').appendChild(box);
}
function counts(c){
  for (const k of ['fix','batch','sup','hum']){
    const el = $('#c-' + k);
    if (el.textContent !== String(c[k])){ el.textContent = c[k]; el.classList.remove('bump'); void el.offsetWidth; el.classList.add('bump'); }
    $('#s-' + k).style.width = (c.total ? c[k] / c.total * 100 : 0) + '%';
  }
  $('#findMeta').textContent = `${c.triaged} of ${c.total} triaged`;
}
function pr(p){
  if (!Object.keys(st.prs).length) $('#prs').innerHTML = '';
  if (st.prs[p.num]) return; st.prs[p.num] = p;
  $('#prs').insertAdjacentHTML('beforeend', `<div class="pr"><a class="num" href="${esc(p.url)}" target="_blank" rel="noopener">#${esc(p.num)}</a>
    <div class="tt" title="${esc(p.title)}">${esc(p.title)}</div>
    <div class="mm"><span class="add">+${p.add}</span><span class="del">−${p.del}</span><span>${p.files} files</span><span>${p.verified ? 'verified ✓' : ''}</span><span class="st">${p.reused ? 'Existing · ' : ''}${esc(p.status)}</span></div></div>`);
  $('#prMeta').textContent = Object.keys(st.prs).length + ' open';
}
function guards(g){
  if (g.masked != null) $('#gMask').textContent = g.masked + ' masked';
  if (g.injections){ $('#gInj').classList.add('hit'); $('#gInjM').textContent = g.injections + ' ignored'; }
  if (g.retries != null){ $('#gRetry').textContent = `${g.retries} used`; $('#gRet').classList.toggle('hit', g.retries > 0); }
  const hits = document.querySelectorAll('.g.hit').length;
  $('#gMeta').textContent = hits ? `${hits} event${hits > 1 ? 's' : ''} logged` : 'all passing';
  if (g.kill != null) killUi(g.kill);
}
function runInfo(r){
  st.run = r; st.budget = r.budget || st.budget;
  $('#rTitle').innerHTML = `PR #${esc(r.pr)} <span class="dot">·</span> ${esc(r.repo.split('/')[1])} <span class="dot">·</span> <span style="font-weight:500;color:var(--ink-2)">${esc(r.title)}</span>`;
  $('#rSub').innerHTML = `Run <b>${esc(String(r.run_id).slice(0,8))}</b> · branch <b>${esc(r.head_ref)}</b> → ${esc(r.base_ref)} · ${r.files} files changed · started <b>${clock(r.started)} IST</b>`;
  const pill = $('#runPill'), s = r.status;
  pill.className = 'pill ' + (s === 'running' ? 'running' : s === 'waiting' ? 'waiting' : s.startsWith('stopped') || s === 'failed' ? 'stopped' : 'done');
  $('#runPillText').textContent = s === 'running' ? 'Running' : s === 'waiting' ? 'Waiting for human review' : s === 'stopped_kill_switch' ? 'Stopped · kill switch' : s === 'stopped_budget' ? 'Stopped · budget' : s === 'failed' ? 'Failed' : s === 'review_recorded' ? 'Review recorded' : s;
  const live = $('#live');
  live.className = s === 'running' ? 'live' : 'live off';
  live.lastElementChild.textContent = s === 'running' ? 'Live' : s === 'waiting' ? 'Paused · awaiting human' : 'Ended';
  $('#reviewBtn').style.display = s === 'waiting' ? '' : 'none';
  if (r.used) { st.total = r.used; renderTokens(); }
  refreshStatusline();
}
function handle(ev){
  if (ev.seq <= st.seq) return; st.seq = ev.seq;
  const d = ev.data;
  switch (ev.type){
    case 'run': runInfo(d); break;
    case 'agent': setAgent(d.id, d.state, d.text, d.tokens); break;
    case 'entry': entry(d, ev.ts); break;
    case 'tool': tool(d); break;
    case 'detail': detail(d); break;
    case 'flag': { const e = st.entries[d.entry]; if (e) setFlag(e, d.flag); break; }
    case 'counts': counts(d); break;
    case 'pr': pr(d); break;
    case 'guards': guards(d); if (d.budget_used != null){ st.total = d.budget_used; renderTokens(); } break;
    case 'tokens': { const a = st.agents[d.agent]; if (a){ a.tok = d.tokens; a.tier = d.tier; } st.total = d.total; st.budget = d.budget; renderTokens(); break; }
    case 'checkpoint': st.checkpoints = d.n; break;
    case 'tasks': $('#tasks').innerHTML = d.map(t => `<div class="task"><b>${esc(t.type)}</b><span>${esc(t.title)}</span></div>`).join(''); break;
  }
  const f = $('#feed'); f.scrollTop = f.scrollHeight;
}
function connect(runId){
  if (es) es.close();
  reset();
  es = new EventSource(`/api/runs/${runId}/events`);
  es.onmessage = m => handle(JSON.parse(m.data));
}
setInterval(() => {
  const r = st && st.run; if (!r) return;
  const end = r.ended ? new Date(r.ended) : new Date();
  const el = (end - new Date(r.started)) / 1000;
  $('#elapsed').textContent = mmss(el);
  if (r.status === 'running'){
    const GLYPHS = ['·','✢','✳','✶','✻','✽','✻','✶','✳','✢'];
    $('#glyph').textContent = GLYPHS[Math.floor(performance.now() / 120) % GLYPHS.length];
    $('#slMeta').textContent = `${mmss(el)} · ${fmtTok(st.total)} tokens${st.checkpoints ? ` · checkpoint ${st.checkpoints}` : ''}`;
  } else $('#slMeta').textContent = `${mmss(el)} · ${fmtTok(st.total)} tokens · ${st.checkpoints} checkpoints`;
}, 150);

$('#prNum').oninput = () => $('#prLbl').textContent = $('#prNum').value;
$('#runBtn').onclick = async () => {
  const r = await fetch('/api/runs', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({pr: +$('#prNum').value, fresh: $('#fresh').checked})});
  const j = await r.json();
  if (!r.ok){ toast(j.error || 'Could not start run'); return; }
  connect(j.run_id); toast('Run started');
};
$('#reviewBtn').onclick = async () => {
  const r = await fetch(`/api/runs/${st.run.run_id}/review`, {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({decision:'reviewed in dashboard'})});
  toast(r.ok ? 'Review recorded (merging stays a human action on GitHub)' : 'No pending review in this process');
};
function killUi(on){
  $('#killSw').classList.toggle('on', on); $('#kill').classList.toggle('on', on);
  $('#killT').textContent = on ? 'Kill switch ON' : 'Kill switch';
  $('#killS').textContent = on ? 'All agents stopped · new runs refused' : 'Stops all agents & cancels in-flight calls';
}
$('#killSw').onclick = async () => {
  const on = !$('#killSw').classList.contains('on');
  const r = await fetch('/api/controls/killswitch', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({on, by:'dashboard'})});
  const j = await r.json(); killUi(j.kill_switch); toast(j.kill_switch ? 'Kill switch ON — run cancelled' : 'Kill switch off');
};

document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('on', v.id === 'v-' + t.dataset.v));
  if (t.dataset.v === 'findings' || t.dataset.v === 'backlog') loadFindings();
  if (t.dataset.v === 'controls') loadControls();
});
async function loadFindings(){
  const fs = await (await fetch('/api/findings')).json();
  const inPr = fs.filter(f => !String(f.scope).startsWith('backlog')), bl = fs.filter(f => String(f.scope).startsWith('backlog'));
  $('#ctFind').textContent = inPr.length; $('#ctBack').textContent = bl.length;
  const row = f => `<tr><td><b>${esc(f.title)}</b><div class="note">${esc(f.file_path || f.component_name || '')}${f.component_version ? ' ' + esc(f.component_version) : ''}</div></td>
    <td>${esc(f.issue_type)}</td><td>${esc(f.source_scanner)}<div class="note">${esc(f.scanner_rule_id)}</div></td>
    <td>${esc(f.severity_scanner)} → <b>${esc(f.severity_effective || '–')}</b></td><td><span class="st ${esc(f.status)}">${esc(f.status)}</span>${f.injection_flag ? ' <span class="flag show inj">injection</span>' : ''}</td>
    <td>${f.decision ? esc(f.decision.decision) + ` <span class="note">(${(+f.decision.confidence).toFixed(2)}, ${esc(f.decision.model_id)})</span><div class="note">${esc(f.decision.reason)}</div>` : '–'}</td>
    <td>${(f.fixes || []).filter(x => x.pr_url).map(x => `<a href="${esc(x.pr_url)}" target="_blank">#${esc(x.pr_url.split('/').pop())}</a>`).join(' ') || '–'}</td>
    <td class="m">${esc(f.fingerprint.slice(0,12))}</td></tr>`;
  const hdr = '<tr><th>Finding</th><th>Type</th><th>Scanner</th><th>Severity (scanner → effective)</th><th>Status</th><th>Triage decision</th><th>Fix PR</th><th>Fingerprint</th></tr>';
  $('#ftable').innerHTML = hdr + (inPr.map(row).join('') || '<tr><td colspan="8" class="note">No findings yet</td></tr>');
  $('#v-backlog').innerHTML = `<div class="panel"><h3>Backlog</h3><div class="note">Slice 1 lists findings that already exist on the base branch (outside PR scope). The Black Duck–style backlog sweep with dedupe, fix groups and burn-down comes in slice 2.</div></div>
    <table class="ft">${hdr}${bl.map(row).join('') || '<tr><td colspan="8" class="note">Empty</td></tr>'}</table>`;
}
async function loadControls(){
  const c = await (await fetch('/api/controls')).json();
  killUi(c.kill_switch);
  const pre = (t, o) => `<div class="panel"><h3>${t}</h3><pre>${esc(JSON.stringify(o, null, 2))}</pre></div>`;
  $('#v-controls').innerHTML = `<div class="panel"><h3>Kill switch</h3><div class="note"><b>${c.kill_switch ? 'ON: runs refused, in-flight runs cancelled' : 'Off'}</b> · toggle on the Live run tab · every change is audited in .data/control</div></div>
    <div class="panel"><h3>Config snapshot</h3><div class="note">${esc(c.config)} · changed only by PR to rules/ (read-only in slice 1)</div></div>` +
    pre('Budgets · thresholds · retries · authority', {budgets:c.budgets, thresholds:c.thresholds, retries:c.retries, authority:c.authority}) +
    pre('Plug-in registry (routing.yaml)', c.routes) + pre('Model tiers (gateway)', c.tiers) + pre('Tool allow-lists (there is no merge tool)', c.tool_allow_lists);
}

reset();
(async () => {
  try { const c = await (await fetch('/api/controls')).json(); killUi(c.kill_switch); $('#cfgLabel').textContent = 'config #' + c.config.split('#')[1] + ' · synthetic data'; } catch {}
  const id = new URLSearchParams(location.search).get('run');
  if (id) connect(id);
  else { const r = await fetch('/api/runs/latest'); if (r.ok){ const j = await r.json(); connect(j.run_id); } }
  loadFindings();
})();
window.__state = () => st;
})();
