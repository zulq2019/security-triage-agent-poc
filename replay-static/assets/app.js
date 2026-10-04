(() => {
const $ = s => document.querySelector(s);
// Replay mode: plays back a recorded run from static JSON with no backend (window.SECAGENT_REPLAY or ?replay=run.json).
const REPLAY = window.SECAGENT_REPLAY || new URLSearchParams(location.search).get('replay');
let nowFn = () => new Date();
let REC = null;   // recorded run (replay mode)
async function getJson(path){
  if (!REPLAY) return (await fetch(path)).json();
  if (path === '/api/findings') return REC ? REC.findings : [];
  if (path === '/api/controls') return REC ? Object.assign({}, REC.controls, {kill_switch:false}) : {};
  throw new Error('no backend in replay mode');
}
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
  { const rb = $('#reviewBtn'); if (rb) rb.style.display = 'none'; }
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
  limitsUi(g);
  const hits = document.querySelectorAll('.g.hit').length;
  $('#gMeta').textContent = hits ? `${hits} event${hits > 1 ? 's' : ''} logged` : 'all passing';
  if (g.kill != null) killUi(g.kill);
}
// max_fixes / max_minutes guardrails (policies.yaml budgets). Fed by 'guards' events and run info.
function limitsUi(g){
  if (g.max_fixes != null){
    $('#gFixT').textContent = `Fix cap (max_fixes ${g.max_fixes > 0 ? g.max_fixes : '∞'})`;
    if (g.deferred != null || g.fixes_dispatched != null)
      $('#gFixM').textContent = g.deferred > 0 ? `${g.deferred} deferred → human` : `${g.fixes_dispatched || 0} dispatched`;
    $('#gFix').classList.toggle('hit', g.deferred > 0);
  }
  if (g.max_minutes != null){
    $('#gTimeT').textContent = `Time budget (max_minutes ${g.max_minutes > 0 ? g.max_minutes : '∞'})`;
    if (g.time_up) $('#gTimeM').textContent = 'time up · run stopped';
    $('#gTime').classList.toggle('hit', !!g.time_up);
  }
  const hits = document.querySelectorAll('.g.hit').length;
  $('#gMeta').textContent = hits ? `${hits} event${hits > 1 ? 's' : ''} logged` : 'all passing';
}
function runInfo(r){
  limitsUi({max_fixes: r.max_fixes, max_minutes: r.max_minutes, time_up: r.stop_detail && String(r.stop_detail).startsWith('budget: max_minutes')});
  if (r.max_minutes > 0 && !(r.stop_detail && String(r.stop_detail).startsWith('budget: max_minutes')) && r.started){
    const mins = Math.round(((r.ended ? new Date(r.ended) : new Date()) - new Date(r.started)) / 60000);
    $('#gTimeM').textContent = `${mins} of ${r.max_minutes} min`;
  }
  st.run = r; st.budget = r.budget || st.budget;
  $('#rTitle').innerHTML = `PR #${esc(r.pr)} <span class="dot">·</span> ${esc(r.repo.split('/')[1])} <span class="dot">·</span> <span style="font-weight:500;color:var(--ink-2)">${esc(r.title)}</span>`;
  $('#rSub').innerHTML = `Run <b>${esc(String(r.run_id).slice(0,8))}</b> · branch <b>${esc(r.head_ref)}</b> → ${esc(r.base_ref)} · ${r.files} files changed · started <b>${clock(r.started)} IST</b>`;
  const pill = $('#runPill'), s = r.status;
  pill.className = 'pill ' + (s === 'running' ? 'running' : s === 'waiting' ? 'waiting' : s.startsWith('stopped') || s === 'failed' ? 'stopped' : 'done');
  $('#runPillText').textContent = s === 'running' ? 'Running' : s === 'waiting' ? 'Waiting for human review' : s === 'stopped_kill_switch' ? 'Stopped · kill switch' : s === 'stopped_budget' ? 'Stopped · budget' : s === 'failed' ? 'Failed' : s === 'review_recorded' ? 'Review recorded' : s;
  const live = $('#live');
  live.className = s === 'running' ? 'live' : 'live off';
  live.lastElementChild.textContent = s === 'running' ? 'Live' : s === 'waiting' ? 'Paused · awaiting human' : 'Ended';
  { const rb = $('#reviewBtn'); if (rb) rb.style.display = s === 'waiting' && !REPLAY ? '' : 'none'; }
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
  const end = r.ended ? new Date(r.ended) : nowFn();
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
  if (REPLAY){ toast('Kill switch is disabled in replay (no backend)'); return; }
  const on = !$('#killSw').classList.contains('on');
  const r = await fetch('/api/controls/killswitch', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({on, by:'dashboard'})});
  const j = await r.json(); killUi(j.kill_switch); toast(j.kill_switch ? 'Kill switch ON — run cancelled' : 'Kill switch off');
};

document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('on', v.id === 'v-' + t.dataset.v));
  if (t.dataset.v === 'findings' || t.dataset.v === 'backlog') loadFindings();
  if (t.dataset.v === 'controls') loadControls();
  if (t.dataset.v === 'usage') loadUsage();
});
async function loadFindings(){
  const fs = await getJson('/api/findings');
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
  const c = await getJson('/api/controls');
  killUi(c.kill_switch);
  const pre = (t, o) => `<div class="panel"><h3>${t}</h3><pre>${esc(JSON.stringify(o, null, 2))}</pre></div>`;
  $('#v-controls').innerHTML = `<div class="panel"><h3>Kill switch</h3><div class="note"><b>${c.kill_switch ? 'ON: runs refused, in-flight runs cancelled' : 'Off'}</b> · toggle on the Live run tab · every change is audited in .data/control</div></div>
    <div class="panel"><h3>Config snapshot</h3><div class="note">${esc(c.config)} · changed only by PR to rules/ (read-only in slice 1)</div></div>` +
    pre('Budgets · thresholds · retries · authority', {budgets:c.budgets, thresholds:c.thresholds, retries:c.retries, authority:c.authority}) +
    pre('Plug-in registry (routing.yaml)', c.routes) + pre('Model tiers (gateway)', c.tiers) + pre('Tool allow-lists (there is no merge tool)', c.tool_allow_lists);
}

// ------------------------------------------------ usage tab ------------------------------------------------
// Live: /api/usage/* (filters applied server-side). Replay: the same filters and aggregation run in the browser (UL below) over
// static rows from run.json: the recorded run's real calls (REC.usage.calls) plus an optional SYNTHETIC sample (REC.usage_sample).
const AGENT_NAMES = {'triage-agent':'Triage', library:'Library fixer', secrets:'Secrets fixer', unsafe_code:'Unsafe code fixer', binary_licence:'Binary/Licence fixer', verifier:'Verifier'};
const PROV_NAMES = {ollama:'Ollama · local', openai:'OpenAI', azureopenai:'Azure OpenAI', mixed:'mixed'};
const us = {range:'7d', from:null, to:null, model:'', agent:'', run:'', synthetic:true, page:1, size:25, facetsKey:''};
const fmtN = n => { n = +n || 0; const a = Math.abs(n); return a >= 1e6 ? (n/1e6).toFixed(2) + 'M' : a >= 1e4 ? (n/1e3).toFixed(1) + 'k' : a >= 1e3 ? (n/1e3).toFixed(2) + 'k' : String(Math.round(n)); };
const fmtUsd = c => { c = +c || 0; return c === 0 ? '$0' : c >= 100 ? '$' + c.toFixed(0) : c >= 1 ? '$' + c.toFixed(2) : '$' + c.toFixed(4); };
const fmtMs = ms => { ms = +ms || 0; return ms >= 60000 ? (ms/60000).toFixed(1) + ' min' : ms >= 1000 ? (ms/1000).toFixed(1) + ' s' : Math.round(ms) + ' ms'; };
const pctS = x => (x * 100).toFixed(1) + '%';
const utcDate = s => new Date(/Z$|[+-]\d\d:\d\d$/.test(s) ? s : s + 'Z');
const istDay = d => new Intl.DateTimeFormat('en-GB', {timeZone:'Asia/Kolkata', day:'2-digit', month:'short'}).format(d);
const istTime = s => new Intl.DateTimeFormat('en-GB', {timeZone:'Asia/Kolkata', day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false}).format(utcDate(s));
const agentName = a => AGENT_NAMES[a] || a;
const costCell = (cost, local, ph) => local ? `$0 <span class="tag local">local model</span>` : fmtUsd(cost) + (ph ? ' <span class="tag ph" title="priced from the placeholder price book in rules/gateway/models.yaml">placeholder price</span>' : '');
function uq(extra){
  const p = new URLSearchParams();
  if (us.range === 'custom' && us.from && us.to){ p.set('from', us.from); p.set('to', us.to); } else p.set('range', us.range === 'custom' ? '7d' : us.range);
  if (us.model) p.set('model', us.model); if (us.agent) p.set('agent', us.agent); if (us.run) p.set('run', us.run);
  if (!us.synthetic) p.set('synthetic', 'exclude');
  for (const [k, v] of Object.entries(extra || {})) p.set(k, v);
  return p.toString();
}
const uapi = async (path, p) => REPLAY ? UL.api(path, p) : (await fetch(`/api/usage/${path}?${p}`)).json();
const uget = (path, extra) => uapi(path, new URLSearchParams(uq(extra)));

// Replay usage engine: a port of /api/usage/{summary,calls,budget,facets,calls.csv} (UsageAggregator, Store.UsageFacets, UsageCsv).
// "Today" is the recorded run's IST day (REC.usage.as_of): the replay is a static snapshot, so presets are anchored there.
const UL = {rows: [], today: null, policy: null, sample: null,
  // C# Math.Round(x, d) rounds half to even; mirror it so the replay shows the same numbers as the API
  rnd(x, d){ const m = Math.pow(10, d), v = x * m, f = Math.floor(v), r = v - f; return (r > 0.5 + 1e-9 || (Math.abs(r - 0.5) <= 1e-9 && f % 2 !== 0) ? f + 1 : f) / m; },
  ymd: ms => new Date(ms + 330 * 60000).toISOString().slice(0, 10),
  addDays: (d, n) => new Date(Date.parse(d + 'T00:00:00Z') + n * 864e5).toISOString().slice(0, 10),
  init(){
    const U = REC && REC.usage; if (!U) return false;
    const S = REC.usage_sample;
    const real = (U.calls || []).map(c => Object.assign({}, c, {synthetic: false}));
    const syn = S ? S.rows.map(r => { const o = Object.fromEntries(S.columns.map((k, i) => [k, r[i]])); o.fallback_used = !!o.fallback_used; o.cache_hit = !!o.cache_hit; o.synthetic = true; o.total_tokens = o.input_tokens + o.output_tokens; return o; }) : [];
    UL.rows = real.concat(syn).map(r => { r._ms = utcDate(r.ts_utc).getTime(); r._day = UL.ymd(r._ms); return r; }).sort((a, b) => a._ms - b._ms);
    UL.today = U.as_of || (U.filter && U.filter.to) || UL.ymd(Date.now());
    UL.policy = U.policy || {budgets: {pr: {tokens: (U.budget && U.budget.runs && U.budget.runs.cap_tokens) || 0}}, usage_budgets: {daily_tokens: 0, monthly_tokens: 0, monthly_cost: 0}};
    UL.sample = S || null;
    return true;
  },
  filter(p){
    const T = UL.today, r = p.get('range') || '7d';
    let from = p.get('from'), to = p.get('to');
    if (!(from && to)){ to = T; from = r === 'today' ? T : r === '30d' ? UL.addDays(T, -29) : UL.addDays(T, -6); }
    if (to < from) [from, to] = [to, from];
    const days = Math.round((Date.parse(to) - Date.parse(from)) / 864e5) + 1;
    const syn = ['exclude', 'only'].includes(p.get('synthetic')) ? p.get('synthetic') : 'include';
    return {from, to, days, tz: 'Asia/Kolkata (IST, UTC+5:30)', model: p.get('model') || null, agent: p.get('agent') || null, provider: p.get('provider') || null,
      task: p.get('task') || null, run: p.get('run') || null, synthetic: syn};
  },
  query(f){
    return UL.rows.filter(r => r._day >= f.from && r._day <= f.to && (!f.model || r.model_id === f.model) && (!f.agent || r.agent_id === f.agent) &&
      (!f.provider || r.provider === f.provider) && (!f.task || r.task_purpose === f.task) && (!f.run || r.run_id === f.run) &&
      (f.synthetic === 'include' || (f.synthetic === 'exclude' ? !r.synthetic : r.synthetic)));
  },
  totals(rows){
    const calls = rows.filter(r => !r.cache_hit), lat = calls.map(r => r.latency_ms).sort((a, b) => a - b);
    const t = {calls: calls.length, cache_hits: rows.length - calls.length,
      input_tokens: rows.reduce((a, r) => a + r.input_tokens, 0), output_tokens: rows.reduce((a, r) => a + r.output_tokens, 0), cost: rows.reduce((a, r) => a + (+r.cost || 0), 0),
      avg_latency_ms: lat.length ? UL.rnd(lat.reduce((a, x) => a + x, 0) / lat.length, 1) : 0,
      p95_latency_ms: lat.length ? lat[Math.min(lat.length - 1, Math.ceil(lat.length * 0.95) - 1)] : 0,
      errors: calls.filter(r => r.outcome === 'error').length, timeouts: calls.filter(r => r.outcome === 'timeout').length,
      retries: calls.filter(r => r.schema_attempts > 1).length, fallbacks: calls.filter(r => r.fallback_used).length,
      runs: new Set(rows.map(r => r.run_id)).size, synthetic_rows: rows.filter(r => r.synthetic).length, real_rows: rows.filter(r => !r.synthetic).length,
      has_placeholder_prices: rows.some(r => r.price_source === 'placeholder'), all_local: rows.every(r => r.provider === 'ollama')};
    t.total_tokens = t.input_tokens + t.output_tokens;
    t.error_rate = t.calls ? UL.rnd((t.errors + t.timeouts) / t.calls, 4) : 0;
    t.retry_rate = t.calls ? UL.rnd(t.retries / t.calls, 4) : 0;
    return t;
  },
  keyOf: (r, by) => by === 'model' ? r.model_id : by === 'agent' ? r.agent_id : by === 'task' ? r.task_purpose : by === 'run' ? r.run_id : by === 'day' ? r._day : r.provider,
  group(rows, by, from, to){
    const all = UL.totals(rows), m = new Map();
    for (const r of rows){ const k = UL.keyOf(r, by); if (!m.has(k)) m.set(k, []); m.get(k).push(r); }
    const r1 = x => UL.rnd(x, 1);
    const groups = [...m].map(([key, list]) => {
      const t = UL.totals(list), first = list[0];
      return {key, provider: new Set(list.map(r => r.provider)).size === 1 ? first.provider : 'mixed',
        ...(by === 'run' ? {repo: first.repo, pr_number: first.pr_number, mode: first.mode} : {}),
        calls: t.calls, cache_hits: t.cache_hits, input_tokens: t.input_tokens, output_tokens: t.output_tokens, total_tokens: t.total_tokens, cost: t.cost,
        avg_latency_ms: t.avg_latency_ms, errors: t.errors + t.timeouts, retries: t.retries,
        pct_tokens: all.total_tokens ? r1(100 * t.total_tokens / all.total_tokens) : 0, pct_cost: all.cost ? r1(100 * t.cost / all.cost) : 0, pct_calls: all.calls ? r1(100 * t.calls / all.calls) : 0,
        local: t.all_local, placeholder: t.has_placeholder_prices, synthetic_rows: t.synthetic_rows, _last: list[list.length - 1]._ms,
        first_utc: first.ts_utc, last_utc: list[list.length - 1].ts_utc};
    });
    if (by === 'day' && from && to){
      const have = new Set(groups.map(g => g.key));
      for (let d = from; d <= to; d = UL.addDays(d, 1)) if (!have.has(d)) groups.push({key: d, calls: 0, cache_hits: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0, cost: 0, avg_latency_ms: 0, errors: 0, retries: 0, pct_tokens: 0, pct_cost: 0, pct_calls: 0, local: true, synthetic_rows: 0});
      return groups.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
    }
    return by === 'run' ? groups.sort((a, b) => b._last - a._last) : groups.sort((a, b) => b.total_tokens - a.total_tokens || b.calls - a.calls);
  },
  budget(win, f){
    const T = UL.today, [y, mo, dd] = T.split('-').map(Number), monthStart = T.slice(0, 8) + '01';
    const daysInMonth = new Date(Date.UTC(y, mo, 0)).getUTCDate(), elapsed = dd, ub = UL.policy.usage_budgets || {}, bud = UL.policy.budgets || {};
    const month = UL.query(Object.assign({}, f, {from: monthStart, to: T}));
    const sumTok = rs => rs.reduce((a, r) => a + r.input_tokens + r.output_tokens, 0);
    const winTokens = sumTok(win), winBudget = (ub.daily_tokens || 0) * f.days, mTokens = sumTok(month), mCost = month.reduce((a, r) => a + (+r.cost || 0), 0);
    const firstCap = (Object.values(bud)[0] || {}).tokens || 0;
    const runs = UL.group(win, 'run').map(g => { const cap = (bud[g.mode || 'pr'] || {}).tokens ?? firstCap;
      return {run_id: g.key, repo: g.repo, pr_number: g.pr_number, mode: g.mode, tokens: g.total_tokens, cap_tokens: cap, cost: g.cost,
        pct: cap ? UL.rnd(100 * g.total_tokens / cap, 1) : 0, synthetic: g.synthetic_rows > 0, last_utc: g.last_utc}; });
    const label = new Intl.DateTimeFormat('en-GB', {month: 'short', year: 'numeric', timeZone: 'UTC'}).format(new Date(monthStart + 'T00:00:00Z'));
    return {
      window: {from: f.from, to: f.to, days: f.days, tokens: winTokens, budget_tokens: winBudget, pct: winBudget ? UL.rnd(100 * winTokens / winBudget, 1) : 0, daily_budget_tokens: ub.daily_tokens || 0},
      month: {label, from: monthStart, to: T, days_elapsed: elapsed, days_in_month: daysInMonth, tokens: mTokens, budget_tokens: ub.monthly_tokens || 0,
        pct_tokens: ub.monthly_tokens ? UL.rnd(100 * mTokens / ub.monthly_tokens, 1) : 0, projected_tokens: Math.round(mTokens / elapsed * daysInMonth),
        cost: mCost, budget_cost: ub.monthly_cost || 0, pct_cost: ub.monthly_cost ? UL.rnd(100 * mCost / ub.monthly_cost, 1) : 0, projected_cost: UL.rnd(mCost / elapsed * daysInMonth, 4)},
      runs: {cap_tokens: (bud.pr || {}).tokens || 0, count: runs.length, avg_pct: runs.length ? UL.rnd(runs.reduce((a, r) => a + r.pct, 0) / runs.length, 1) : 0,
        max_pct: runs.length ? Math.max(...runs.map(r => r.pct)) : 0, over_80: runs.filter(r => r.pct >= 80).length, items: runs.slice(0, 12)},
    };
  },
  facets(f){
    const rows = UL.query({from: f.from, to: f.to, synthetic: f.synthetic});
    const models = new Map(); rows.forEach(r => models.set(r.model_id, r.provider));
    const runs = UL.group(rows, 'run').slice(0, 200).map(g => ({run_id: g.key, repo: g.repo, pr_number: g.pr_number, synthetic: g.synthetic_rows > 0 ? 1 : 0, last_utc: g.last_utc}));
    return {models: [...models].sort((a, b) => a[0] < b[0] ? -1 : 1).map(([model, provider]) => ({model, provider})), agents: [...new Set(rows.map(r => r.agent_id))].sort(),
      runs, any_synthetic: UL.rows.some(r => r.synthetic)};
  },
  csv(rows){
    const C = v => { const s = v == null ? '' : String(v); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const ist = ms => new Date(ms + 330 * 60000).toISOString().slice(0, 19).replace('T', ' ') + ' IST';
    const head = 'ts_utc,ts_ist,run_id,repo,pr_number,mode,agent_id,task_purpose,tier,model_id,model_version,deployment,provider,input_tokens,output_tokens,total_tokens,latency_ms,cost_usd,price_source,outcome,outcome_detail,schema_attempts,fallback_used,cache_hit,synthetic\n';
    return head + rows.map(u => [new Date(u._ms).toISOString().slice(0, 19) + 'Z', ist(u._ms), u.run_id, u.repo, u.pr_number, u.mode, u.agent_id, u.task_purpose, u.tier, u.model_id,
      u.model_version, u.deployment, u.provider, u.input_tokens, u.output_tokens, u.input_tokens + u.output_tokens, u.latency_ms, +u.cost || 0, u.price_source, u.outcome, u.outcome_detail,
      u.schema_attempts, u.fallback_used ? 1 : 0, u.cache_hit ? 1 : 0, u.synthetic ? 1 : 0].map(C).join(',')).join('\n') + (rows.length ? '\n' : '');
  },
  async api(path, p){
    const f = UL.filter(p), rows = UL.query(f), out = x => JSON.parse(JSON.stringify(x));
    if (path === 'summary'){ const by = p.get('groupBy'); return out({filter: f, totals: UL.totals(rows), group_by: by, groups: by ? UL.group(rows, by, f.from, f.to) : null}); }
    if (path === 'calls'){
      const page = Math.max(1, +p.get('page') || 1), size = Math.min(500, Math.max(1, +p.get('pageSize') || 25)), desc = rows.slice().reverse();
      return out({filter: f, page, page_size: size, total: rows.length, pages: Math.ceil(rows.length / size), items: desc.slice((page - 1) * size, page * size)});
    }
    if (path === 'budget') return out(UL.budget(rows, f));
    if (path === 'facets') return out(UL.facets(f));
    if (path === 'calls.csv'){
      const name = `secagent-usage_${f.from.replace(/-/g, '')}-${f.to.replace(/-/g, '')}${f.synthetic === 'exclude' ? '_real' : rows.some(r => r.synthetic) ? '_incl-synthetic' : ''}.csv`;
      return {name, text: UL.csv(rows)};
    }
    throw new Error('unknown usage path ' + path);
  }};

async function loadUsage(){
  let sum, day, model, agent, task, calls, budget;
  if (REPLAY && !UL.today){ $('#uKpis').innerHTML = '<div class="u-empty" style="grid-column:1/-1">This replay was exported without usage data.</div>'; return; }
  [sum, day, model, agent, task, calls, budget] = await Promise.all([uget('summary'), uget('summary', {groupBy:'day'}), uget('summary', {groupBy:'model'}),
    uget('summary', {groupBy:'agent'}), uget('summary', {groupBy:'task'}), uget('calls', {page: us.page, pageSize: us.size}), uget('budget')]);
  day = day.groups; model = model.groups; agent = agent.groups; task = task.groups;
  loadFacets();
  $('#uCsv').href = REPLAY ? '#' : '/api/usage/calls.csv?' + uq();
  const t = sum.totals, f = sum.filter;
  { const sb = $('#uSynBadge'); if (sb) sb.style.display = t.synthetic_rows > 0 ? '' : 'none'; }
  $('#uSub').innerHTML = `<span><b>${esc(f.from)}</b> → <b>${esc(f.to)}</b> IST · ${f.days} day${f.days > 1 ? 's' : ''}</span><span>·</span><span>${t.runs} run${t.runs === 1 ? '' : 's'} · ${fmtN(t.real_rows)} real row${t.real_rows === 1 ? '' : 's'}${t.synthetic_rows ? ` · <b style="color:#8a5a00">${fmtN(t.synthetic_rows)} synthetic</b>` : ''}</span>` +
    (us.model || us.agent || us.run ? `<span>·</span><span>filtered: ${[us.model && 'model ' + esc(us.model), us.agent && 'agent ' + esc(agentName(us.agent)), us.run && 'run ' + esc(us.run.slice(0, 8))].filter(Boolean).join(', ')}</span>` : '') +
    (REPLAY ? `<span>·</span><span>static snapshot as of <b>${esc(istDay(new Date(UL.today + 'T00:00:00+05:30')))} ${UL.today.slice(0, 4)}</b> IST (no backend)</span>` +
      (t.synthetic_rows ? `<span class="u-synnote"><b>Synthetic sample data:</b> generated rows (seed ${esc(UL.sample && UL.sample.seed)}) for fictional <code>synthetic-org/*</code> repos, mixed with the ${fmtN(t.real_rows)} real call${t.real_rows === 1 ? '' : 's'} of recorded run ${esc(REC.run.run_id.slice(0, 8))}. Hosted model names and prices are <b>placeholders</b>, not real or current prices. Turn off “Show synthetic” for real usage only.</span>` : '') : '');
  const errRate = t.error_rate, retRate = t.retry_rate;
  $('#uKpis').innerHTML = [
    ['Model calls', fmtN(t.calls), t.cache_hits ? `<b>${fmtN(t.cache_hits)}</b> cache hits (no tokens)` : `${t.runs} run${t.runs === 1 ? '' : 's'} in range`],
    ['Input tokens', fmtN(t.input_tokens), `${t.total_tokens ? pctS(t.input_tokens / t.total_tokens) : '0%'} of all tokens`],
    ['Output tokens', fmtN(t.output_tokens), `${t.calls ? fmtN(t.output_tokens / t.calls) : 0} per call`],
    ['Cost', t.all_local ? '$0' : fmtUsd(t.cost), t.all_local ? '<span class="tag local">local models</span> no API spend' : t.has_placeholder_prices ? '<span class="tag ph">incl. placeholder prices</span>' : 'from configured prices'],
    ['Avg latency', fmtMs(t.avg_latency_ms), `p95 <b>${fmtMs(t.p95_latency_ms)}</b> per call`],
    ['Error / retry rate', `${pctS(errRate)} <span style="font-size:15px;color:var(--ink-3);font-weight:600">/ ${pctS(retRate)}</span>`, `${t.errors} errors · ${t.timeouts} timeouts · ${t.retries} JSON retries · ${t.fallbacks} fallbacks`, errRate > 0.05],
  ].map(([k, v, s, warn]) => `<div class="kpi${warn ? ' warn' : ''}"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s}</div></div>`).join('');
  renderChart(day, t);
  $('#uByModel').innerHTML = groupTable(model, 'Model', g => `<span class="nm">${esc(g.key)}</span> <span class="tag prov">${esc(PROV_NAMES[g.provider] || g.provider)}</span>${g.synthetic_rows ? ' <span class="tag syn">synthetic</span>' : ''}`);
  $('#uByAgent').innerHTML = groupTable(agent, 'Agent', g => `<span class="nm">${esc(agentName(g.key))}</span>${g.synthetic_rows === g.calls + g.cache_hits && g.synthetic_rows ? ' <span class="tag syn">synthetic</span>' : ''}`);
  $('#uByTask').innerHTML = groupTable(task, 'Task', g => `<span class="nm">${esc(g.key)}</span>`);
  $('#uModelMeta').textContent = `${model.length} model${model.length === 1 ? '' : 's'}`; $('#uAgentMeta').textContent = `${agent.length} agent${agent.length === 1 ? '' : 's'}`;
  renderBurn(budget);
  renderCalls(calls);
}
function groupTable(groups, label, nameFn){
  if (!groups.length) return '<div class="u-empty">No model calls in this range</div>';
  return `<table class="ut"><tr><th>${label}</th><th>Calls</th><th>Input</th><th>Output</th><th>Cost</th><th>Avg latency</th><th>% of tokens</th></tr>` + groups.map(g => `<tr>
    <td class="l">${nameFn(g)}</td><td>${fmtN(g.calls)}${g.cache_hits ? ` <span class="tag cache" title="decisions reused without a model call">+${g.cache_hits} cached</span>` : ''}</td><td>${fmtN(g.input_tokens)}</td><td>${fmtN(g.output_tokens)}</td>
    <td>${costCell(g.cost, g.local, g.placeholder)}</td><td>${fmtMs(g.avg_latency_ms)}</td>
    <td><span class="pct"><span class="pb"><i style="width:${Math.min(100, g.pct_tokens)}%"></i></span>${g.pct_tokens.toFixed(1)}%</span></td></tr>`).join('') + '</table>';
}
function renderChart(days, t){
  const el = $('#uChart'), W = Math.max(600, el.clientWidth || 1100), H = 250, L = 52, R = t.all_local ? 16 : 58, T = 12, B = 28;
  const iw = W - L - R, ih = H - T - B, n = days.length || 1;
  const maxTok = Math.max(1, ...days.map(d => d.input_tokens + d.output_tokens)), maxCost = Math.max(...days.map(d => d.cost), 0);
  const nice = v => { const p = Math.pow(10, Math.floor(Math.log10(v))); return [1, 2, 2.5, 5, 10].map(m => m * p).find(x => x >= v); };
  const yMax = nice(maxTok * 1.08), cMax = maxCost > 0 ? nice(maxCost * 1.08) : 1;
  const bw = iw / n, barW = Math.max(2, Math.min(34, bw * 0.62));
  const y = v => T + ih - v / yMax * ih, yc = v => T + ih - v / cMax * ih;
  let g = '';
  for (let i = 0; i <= 4; i++){
    const v = yMax * i / 4, yy = y(v);
    g += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}" stroke="${i ? '#eef2f4' : '#dfe5e8'}"/><text x="${L - 8}" y="${yy + 3.5}" text-anchor="end">${fmtN(v)}</text>`;
    if (!t.all_local && maxCost > 0) g += `<text x="${W - R + 8}" y="${yy + 3.5}">${fmtUsd(cMax * i / 4)}</text>`;
  }
  const every = Math.ceil(n / 15);
  const pts = [];
  days.forEach((d, i) => {
    const cx = L + bw * i + bw / 2, x0 = cx - barW / 2, yi = y(d.input_tokens), yo = y(d.input_tokens + d.output_tokens);
    const date = new Date(d.key + 'T00:00:00+05:30');
    const tip = `${istDay(date)} (IST) · ${fmtN(d.calls)} calls · in ${fmtN(d.input_tokens)} · out ${fmtN(d.output_tokens)} · ${d.local ? '$0 (local)' : fmtUsd(d.cost)}${d.synthetic_rows ? ' · synthetic' : ''}`;
    g += `<g><title>${esc(tip)}</title><rect class="hov" x="${L + bw * i}" y="${T}" width="${bw}" height="${ih}"/>` +
      (d.input_tokens ? `<rect class="bar" x="${x0}" y="${yi}" width="${barW}" height="${T + ih - yi}" fill="#0f7c7c" rx="2"/>` : '') +
      (d.output_tokens ? `<rect class="bar" x="${x0}" y="${yo}" width="${barW}" height="${yi - yo}" fill="#9fd8d4" rx="2"/>` : '') + '</g>';
    if (i % every === 0 || i === n - 1) g += `<text x="${cx}" y="${H - 8}" text-anchor="middle">${istDay(date)}</text>`;
    pts.push([cx, yc(d.cost)]);
  });
  const showCost = !t.all_local && maxCost > 0;
  if (showCost && pts.length) g += `<polyline points="${pts.map(p => p.join(',')).join(' ')}" fill="none" stroke="#c77700" stroke-width="2" stroke-linejoin="round"/>` + pts.map(p => `<circle cx="${p[0]}" cy="${p[1]}" r="2.6" fill="#fff" stroke="#c77700" stroke-width="1.6"/>`).join('');
  el.innerHTML = `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Daily input and output tokens with cost">${g}</svg>`;
  $('#uCostLeg').style.display = showCost ? '' : 'none';
  $('#uChartNote').innerHTML = !t.calls ? 'No model calls in this range.' : showCost ? (t.has_placeholder_prices ? 'Cost uses <b>placeholder prices</b> from rules/gateway/models.yaml for hosted models; local models are $0.' : '') :
    'Cost line hidden: every call in view ran on a local Ollama model ($0).';
}
function meter(label, used, cap, fmt, note){
  const pct = cap ? used / cap * 100 : 0;
  return `<div><div class="row"><span>${label}</span><span><b>${fmt(used)}</b> / ${cap ? fmt(cap) : '–'} · ${cap ? pct.toFixed(1) + '%' : 'no budget set'}</span></div>
    <div class="meter"><i class="${pct >= 80 ? 'hot' : ''}" style="width:${Math.min(100, pct)}%"></i></div>${note ? `<div class="note">${note}</div>` : ''}</div>`;
}
function renderBurn(b){
  const m = b.month, w = b.window, r = b.runs;
  $('#uBurn').innerHTML =
    meter(`Tokens · ${esc(m.label)} to date`, m.tokens, m.budget_tokens, fmtN, `projected month end <b>${fmtN(m.projected_tokens)}</b> at the current rate (day ${m.days_elapsed} of ${m.days_in_month})`) +
    meter(`Cost · ${esc(m.label)} to date`, m.cost, m.budget_cost, fmtUsd, `projected <b>${fmtUsd(m.projected_cost)}</b>${m.cost === 0 ? ' · local models only' : ''}`) +
    meter(`Tokens · selected ${w.days} day${w.days > 1 ? 's' : ''}`, w.tokens, w.budget_tokens, fmtN, `daily budget ${fmtN(w.daily_budget_tokens)} × ${w.days}`) +
    `<div><div class="row"><span>Per-run token cap (${fmtN(r.cap_tokens)})</span><span>avg <b>${r.avg_pct}%</b> · max <b>${r.max_pct}%</b> · ${r.over_80} over 80%</span></div>
      <div class="runbars">${(r.items || []).slice(0, 8).map(x => `<div class="rb"><span title="${esc(x.repo || '')}">${esc((x.repo || '').split('/').pop())}${x.pr_number ? ' #' + x.pr_number : ''}</span>
        <span class="t"><i class="${x.synthetic ? 'syn' : ''}" style="width:${Math.min(100, x.pct)}%"></i></span><span>${x.pct}%</span></div>`).join('') || '<span class="note">No runs in range</span>'}</div></div>`;
}
function callsTable(items, withRun){
  if (!items.length) return '<div class="u-empty">No model calls in this range</div>';
  return `<table class="ut"><tr><th>Time (IST)</th>${withRun ? '<th class="l">Run</th><th class="l">Repo / PR</th>' : ''}<th class="l">Agent</th><th class="l">Task</th><th class="l">Tier</th><th class="l">Model</th><th>Input</th><th>Output</th><th>Cost</th><th>Latency</th><th>Outcome</th></tr>` +
    items.map(c => `<tr><td class="l m">${esc(istTime(c.ts_utc))}</td>` +
      (withRun ? `<td class="l"><a class="runlink" data-run="${esc(c.run_id)}">${esc(c.run_id.slice(0, 8))}</a>${c.synthetic ? ' <span class="tag syn">synthetic</span>' : ''}</td><td class="l">${esc((c.repo || '–').split('/').pop())}${c.pr_number ? ' #' + c.pr_number : ''} <span class="note">${esc(c.mode)}</span></td>` : '') +
      `<td class="l">${esc(agentName(c.agent_id))}</td><td class="l">${esc(c.task_purpose)}</td><td class="l"><span class="chip-m ${c.tier === 'strong' ? 'strong' : 'small'}">${esc(c.tier)}</span></td>
      <td class="l">${esc(c.model_id)}</td><td>${c.cache_hit ? '<span class="tag cache">cache hit</span>' : fmtN(c.input_tokens)}</td><td>${c.cache_hit ? '–' : fmtN(c.output_tokens)}</td>
      <td>${costCell(c.cost, c.provider === 'ollama', c.price_source === 'placeholder')}</td><td>${c.cache_hit ? '–' : fmtMs(c.latency_ms)}</td>
      <td><span class="oc ${esc(c.outcome)}" title="${esc(c.outcome_detail || '')}">${esc(c.outcome.replace('_', ' '))}</span></td></tr>`).join('') + '</table>';
}
function renderCalls(p){
  $('#uCalls').innerHTML = callsTable(p.items, true);
  const a = p.total ? (p.page - 1) * p.page_size + 1 : 0, b = Math.min(p.total, p.page * p.page_size);
  $('#uPager').innerHTML = `<span>${a}–${b} of ${fmtN(p.total)}</span><button class="btn" id="uPrev" ${p.page <= 1 ? 'disabled' : ''}>Previous</button><button class="btn" id="uNext" ${p.page >= p.pages ? 'disabled' : ''}>Next</button>`;
  $('#uPrev').onclick = () => { us.page--; loadUsage(); };
  $('#uNext').onclick = () => { us.page++; loadUsage(); };
  document.querySelectorAll('#uCalls .runlink').forEach(x => x.onclick = () => openRun(x.dataset.run));
}
async function openRun(runId){
  const d = $('#uDrawer');
  let items, t;
  {
    const q = new URLSearchParams({range:'30d', run: runId, pageSize: 500}); if (!us.synthetic) q.set('synthetic', 'exclude');
    // a run can be older than 30 days: widen the window to a year for the drill-down
    q.delete('range'); const to = REPLAY ? new Date(UL.today + 'T12:00:00+05:30') : new Date(); const from = new Date(to.getTime() - 365 * 864e5);
    const ymd = x => new Intl.DateTimeFormat('en-CA', {timeZone:'Asia/Kolkata'}).format(x);
    q.set('from', ymd(from)); q.set('to', ymd(to));
    const [c, s] = await Promise.all([uapi('calls', q), uapi('summary', q)]);
    items = c.items.slice().reverse(); t = s.totals;
  }
  const first = items[0] || {}, syn = items.some(x => x.synthetic);
  d.innerHTML = `<div class="dh"><div><h3>Run ${esc(runId.slice(0, 8))} ${syn ? '<span class="tag syn">synthetic</span>' : ''}</h3>
      <div class="sub">${esc(first.repo || '–')}${first.pr_number ? ' · PR #' + first.pr_number : ''} · ${esc(first.mode || '')} mode · ${first.ts_utc ? esc(istTime(first.ts_utc)) + ' IST' : ''}</div></div>
      <button class="x" id="uX" aria-label="Close">✕</button></div>
    <div class="db">
      <div class="kpis">${[['Calls', fmtN(t.calls) + (t.cache_hits ? ` <span style="font-size:12px;color:var(--ink-3)">+${t.cache_hits} cached</span>` : '')], ['Tokens', fmtN(t.total_tokens)],
        ['Cost', t.all_local ? '$0' : fmtUsd(t.cost)], ['Model time', fmtMs(items.reduce((a, x) => a + (x.cache_hit ? 0 : x.latency_ms), 0))]].map(([k, v]) => `<div class="kpi"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('')}</div>
      <div class="acts"><button class="btn" id="uOnly">Filter Usage to this run</button>${syn ? '<span class="note">Synthetic run: no recorded events or Live run view.</span>' : REPLAY ? (runId === REC.run.run_id ? `<button class="btn" id="uLive">Open in Live run replay</button>` : '') : `<a class="btn" href="/?run=${esc(runId)}">Open in Live run</a>`}</div>
      ${callsTable(items, false)}
    </div>`;
  d.classList.add('open');
  $('#uX').onclick = () => d.classList.remove('open');
  const o = $('#uOnly'); if (o) o.onclick = () => { us.run = runId; us.page = 1; d.classList.remove('open'); loadUsage(); };
  const lv = $('#uLive'); if (lv) lv.onclick = () => { d.classList.remove('open'); document.querySelector('.tab[data-v="live"]').click(); };
}
async function loadFacets(){
  const key = uq({}).replace(/&?(model|agent|run)=[^&]*/g, '');
  if (key === us.facetsKey) return; us.facetsKey = key;
  const p = new URLSearchParams(key);
  const fc = await uapi('facets', p);
  const fill = (sel, all, opts, cur) => { $(sel).innerHTML = `<option value="">${all}</option>` + opts.map(([v, l]) => `<option value="${esc(v)}" ${v === cur ? 'selected' : ''}>${esc(l)}</option>`).join(''); };
  fill('#uModel', 'All models', fc.models.map(m => [m.model, `${m.model} · ${PROV_NAMES[m.provider] || m.provider}`]), us.model);
  fill('#uAgent', 'All agents', fc.agents.map(a => [a, agentName(a)]), us.agent);
  fill('#uRun', 'All runs', fc.runs.map(r => [r.run_id, `${r.run_id.slice(0, 8)} · ${(r.repo || '').split('/').pop()}${r.pr_number ? ' #' + r.pr_number : ''}${r.synthetic ? ' · synthetic' : ''}`]), us.run);
  $('#uSynTog').style.display = fc.any_synthetic ? '' : 'none';
}
function initUsage(){
  const ymd = x => new Intl.DateTimeFormat('en-CA', {timeZone:'Asia/Kolkata'}).format(x);
  $('#uTo').value = ymd(new Date()); $('#uFrom').value = ymd(new Date(Date.now() - 13 * 864e5));
  document.querySelectorAll('#uRange button').forEach(b => b.onclick = () => {
    us.range = b.dataset.r; us.page = 1;
    document.querySelectorAll('#uRange button').forEach(x => x.classList.toggle('on', x === b));
    $('#uCustom').style.display = us.range === 'custom' ? '' : 'none';
    if (us.range === 'custom'){ us.from = $('#uFrom').value; us.to = $('#uTo').value; }
    loadUsage();
  });
  ['#uFrom', '#uTo'].forEach(s => $(s).onchange = () => { us.from = $('#uFrom').value; us.to = $('#uTo').value; us.page = 1; if (us.from && us.to) loadUsage(); });
  [['#uModel', 'model'], ['#uAgent', 'agent'], ['#uRun', 'run']].forEach(([s, k]) => $(s).onchange = () => { us[k] = $(s).value; us.page = 1; loadUsage(); });
  $('#uSynSw').onclick = () => { us.synthetic = !us.synthetic; $('#uSynSw').classList.toggle('on', us.synthetic); us.page = 1; us.facetsKey = ''; loadUsage(); };
  window.addEventListener('resize', () => { if ($('#v-usage').classList.contains('on')) loadUsage(); });
  $('#uCsv').addEventListener('click', async e => {   // replay: build the CSV in the browser (same columns as /api/usage/calls.csv)
    if (!REPLAY) return;
    e.preventDefault(); if (!UL.today) return;
    const {name, text} = await uapi('calls.csv', new URLSearchParams(uq()));
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], {type: 'text/csv;charset=utf-8'})); a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    toast('CSV exported: ' + name);
  });
}
// Replay: anchor the Usage tab at the recorded run's IST day; default view = last 30 days with the synthetic sample (if exported) on.
function initReplayUsage(){
  if (!UL.init()) return;
  us.range = '30d'; us.synthetic = true; us.facetsKey = '';
  document.querySelectorAll('#uRange button').forEach(x => x.classList.toggle('on', x.dataset.r === '30d'));
  $('#uSynSw').classList.add('on');
  $('#uTo').value = UL.today; $('#uFrom').value = UL.addDays(UL.today, -13);
  const td = document.querySelector('#uRange button[data-r="today"]'); if (td) td.title = 'Recorded run day (' + UL.today + ' IST): the replay is a static snapshot';
}
initUsage();
// Trends tab (replay only, sample data): its filters and buttons are illustrative and not wired to data.
document.querySelectorAll('#v-trends [data-mock]').forEach(b => b.onclick = () => toast('Sample view: Trends filters and exports are not wired to data'));
window.__usage = us; window.__ul = UL; Object.defineProperty(window, "__rec", {get: () => REC});

// ------------------------------------------------ replay ------------------------------------------------
const rp = {events: [], i: 0, speed: 1, vt: 0, last: 0, timer: null};
function replayTick(){
  const now = performance.now(); rp.vt += (now - rp.last) * rp.speed; rp.last = now;
  while (rp.i < rp.events.length && Date.parse(rp.events[rp.i].ts) <= rp.vt) handle(rp.events[rp.i++]);
  $('#rpPos').textContent = `${rp.i}/${rp.events.length} events`;
  if (rp.i < rp.events.length) rp.timer = setTimeout(replayTick, 40);
  else { $('#rpPos').textContent = `${rp.events.length} events · replay finished`; loadFindings(); }
}
function replayStart(){
  clearTimeout(rp.timer); reset(); st.seq = 0; rp.i = 0;
  rp.vt = Date.parse(rp.events[0].ts) - 300; rp.last = performance.now();
  replayTick();
}
async function initReplay(){
  REC = window.SECAGENT_RUN || await (await fetch(REPLAY)).json();
  rp.events = REC.events.slice().sort((a, b) => a.seq - b.seq);
  nowFn = () => new Date(rp.vt);
  document.title = 'Replay of a recorded run · Security Triage & Fix Agent';
  $('.controls').innerHTML = `<span class="chk" id="rpPos"></span>
    <div class="seg" id="rpSpeed"><button data-s="1" class="on">1×</button><button data-s="2">2×</button></div>
    <button class="btn primary" id="rpBtn"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg>Replay</button>`;
  $('#rpBtn').onclick = () => { replayStart(); toast(`Replaying at ${rp.speed}×`); };
  document.querySelectorAll('#rpSpeed button').forEach(b => b.onclick = () => {
    rp.speed = +b.dataset.s; document.querySelectorAll('#rpSpeed button').forEach(x => x.classList.toggle('on', x === b));
  });
  const when = new Date(REC.run.started_at + 'Z');
  const ist = new Intl.DateTimeFormat('en-GB', {timeZone: 'Asia/Kolkata', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'}).format(when);
  $('#cfgLabel').innerHTML = `<b style="color:#f5b544">Replay of a recorded run</b> · recorded ${ist} IST · real timings · synthetic data`;
  const banner = document.createElement('div');
  banner.className = 'replay-banner';
  banner.innerHTML = `<b>Replay of a recorded run</b> · run ${esc(REC.run.run_id.slice(0, 8))} · ${esc(REC.provider || '')} · ${Math.round(REC.duration_seconds || 0)} s recorded · no backend: actions are disabled, links go to the real PRs`;
  document.querySelector('.runbar').before(banner);
  initReplayUsage();
  loadFindings();
  replayStart();
}

reset();
(async () => {
  const tabFromQuery = () => { const tab = new URLSearchParams(location.search).get('tab'); const el = tab && document.querySelector(`.tab[data-v="${tab}"]`); if (el) el.click(); };
  if (REPLAY) { await initReplay(); tabFromQuery(); return; }
  try { const c = await (await fetch('/api/controls')).json(); killUi(c.kill_switch); $('#cfgLabel').textContent = 'config #' + c.config.split('#')[1] + ' · synthetic data'; } catch {}
  tabFromQuery();
  const id = new URLSearchParams(location.search).get('run');
  if (id) connect(id);
  else { const r = await fetch('/api/runs/latest'); if (r.ok){ const j = await r.json(); connect(j.run_id); } }
  loadFindings();
})();
window.__state = () => st;
})();
