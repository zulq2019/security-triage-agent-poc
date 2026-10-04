"""Builds src/SecAgent.Dashboard/replay/trends.html: the Trends tab for the no-backend replay (scripts/build-replay.sh injects it
after the Usage tab). Ported from the static mockup sec-agent-sdd/trends-mockup/build_mockup.py: same layout, dashboard design
tokens, inline SVG charts. ALL NUMBERS ARE SYNTHETIC SAMPLE DATA (illustrative only); CVE ids are CVE-SAMPLE-*; KPI targets are
[placeholders]. Nothing here is computed from real runs.
  python3 scripts/build-trends-sample.py"""
import os, html
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "SecAgent.Dashboard", "replay", "trends.html")

NAVY, TEAL, INK2, INK3, LINE = "#12303a", "#0f7c7c", "#4a5b62", "#7a8a91", "#e4e9ec"
SEV = {"Critical": "#c23a3a", "High": "#d4570f", "Medium": "#b26a00", "Low": "#8aa4ad"}
FIX = {"library": "#0f7c7c", "secrets": "#2463c7", "unsafe-code": "#5b3fb5", "binary-licence": "#1a7f4b"}
WEEKS = [f"wk {i}" for i in range(1, 13)]

# ---------------- synthetic sample data ----------------
opened = [14, 11, 16, 12, 9, 13, 10, 8, 11, 7, 9, 6]
fixed = [9, 12, 14, 15, 14, 13, 15, 14, 12, 13, 12, 11]
open0 = {"Critical": 6, "High": 22, "Medium": 38, "Low": 30}
share_end = {"Critical": 0.03, "High": 0.22, "Medium": 0.41, "Low": 0.34}
tot = [sum(open0.values())]
for o, f in zip(opened, fixed): tot.append(tot[-1] + o - f)
tot = tot[1:]
burn = {}
for s in SEV:
    a = open0[s] / sum(open0.values()); b = share_end[s]
    burn[s] = [round(tot[i] * (a + (b - a) * i / 11)) for i in range(12)]
ttf = [("Critical", 2.5, 6), ("High", 7, 18), ("Medium", 19, 41), ("Low", 34, 70)]   # p50, p90 days
merge = {"library": [62, 64, 66, 65, 69, 71, 70, 73, 74, 76, 75, 78], "secrets": [70, 72, 71, 74, 76, 75, 78, 80, 79, 81, 82, 83],
         "unsafe-code": [44, 47, 46, 50, 49, 52, 55, 54, 57, 58, 60, 61], "binary-licence": [80, 82, 81, 84, 83, 85, 86, 85, 87, 88, 87, 89]}
quality = [  # agent, trend, metric label, value, tokens/fix
    ("triage", [9, 9, 8, 8, 7, 7, 7, 6, 6, 6, 5, 5], "overrides", "5%", "—"),
    ("library", [.4, .4, .3, .3, .3, .3, .2, .2, .2, .2, .2, .2], "retries", "0.2", "3.1k"),
    ("secrets", [.2, .2, .2, .1, .1, .1, .1, .1, .1, .1, .1, .1], "retries", "0.1", "2.4k"),
    ("unsafe-code", [.9, .8, .8, .8, .7, .7, .6, .6, .6, .5, .5, .5], "retries", "0.5", "6.2k"),
    ("binary-licence", [.1, .1, .1, .1, .1, .1, .0, .0, .0, .0, .0, .0], "retries", "0.0", "1.8k"),
]
offenders = [("orders-api", "Team A", "SQL built by string concatenation", 9, 3, [0, 1, 1, 0, 2, 1, 0, 1, 1, 0, 1, 1]),
             ("portal-ui", "Team B", "innerHTML with user input", 7, 2, [1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0]),
             ("billing-svc", "Team C", "outdated Sample.Json (transitive)", 6, 1, [0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0]),
             ("reports-job", "Team A", "secret in appsettings.json", 4, 2, [0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0]),
]
age = [("orders-api", [1, 2, 3, 1]), ("portal-ui", [0, 2, 1, 2]), ("billing-svc", [1, 1, 2, 0]), ("reports-job", [0, 1, 0, 1]),
       ("patient-portal", [0, 0, 1, 0])]
AGE = [("0–7 d", "#8fd4d1"), ("8–30 d", "#e3b04b"), ("31–90 d", "#d4570f"), ("> 90 d", "#c23a3a")]
expiring = [("RA-S-014", "orders-api", "High", "vendored GPL-3.0 code", 6), ("RA-S-009", "billing-svc", "High", "Sample.Json 9.x pinned", 13),
            ("RA-S-021", "portal-ui", "Critical", "legacy auth callback", 24)]
licence = [("GPL-3.0", 2), ("AGPL-3.0", 1), ("LGPL-2.1", 3), ("Unknown", 4)]
warnings = [("crit", "CVE-SAMPLE-0001 · critical", "Sample.Logging 2.1.x is used in 7 repos. 7 findings opened, 2 human tasks raised."),
            ("high", "Spreading package", "Sample.Pdf 4.0 (flagged licence) added to 3 more repos in 4 weeks."),
            ("med", "CVE-SAMPLE-0002 · high", "Sample.Http 1.4 in 2 repos. Fix version available; library fixer queued.")]

# ---------------- SVG helpers ----------------
def svg(w, h, body): return f'<svg viewBox="0 0 {w} {h}" width="100%" style="display:block" xmlns="http://www.w3.org/2000/svg" font-family="Inter,system-ui,Segoe UI,Arial,sans-serif">{body}</svg>'
def t(x, y, s, size=12, fill=INK3, anchor="start", weight=400): return f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" font-weight="{weight}">{html.escape(str(s))}</text>'
def axes(x0, y0, x1, y1, ymax, step, fmt=lambda v: str(v)):
    o = ""
    v = 0
    while v <= ymax:
        y = y1 - (y1 - y0) * v / ymax
        o += f'<line x1="{x0}" x2="{x1}" y1="{y:.1f}" y2="{y:.1f}" stroke="{LINE}" stroke-width="1"/>' + t(x0 - 6, y + 4, fmt(v), 11, INK3, "end")
        v += step
    return o
def xlabels(x0, x1, y, labels, every=1):
    n = len(labels); o = ""
    for i, l in enumerate(labels):
        if i % every == 0: o += t(x0 + (x1 - x0) * (i + 0.5) / n, y, l, 11, INK3, "middle")
    return o

def chart_opened_fixed(w=392, h=230):
    x0, y0, x1, y1 = 34, 12, w - 8, h - 46; ymax = 20
    o = axes(x0, y0, x1, y1, ymax, 5)
    bw = (x1 - x0) / 12
    for i, (a, b) in enumerate(zip(opened, fixed)):
        bx = x0 + i * bw
        for k, (v, col) in enumerate(((a, "#e3b04b"), (b, TEAL))):
            hh = (y1 - y0) * v / ymax
            o += f'<rect x="{bx + 4 + k * (bw - 8) / 2:.1f}" y="{y1 - hh:.1f}" width="{(bw - 10) / 2:.1f}" height="{hh:.1f}" rx="2" fill="{col}"/>'
    o += xlabels(x0, x1, y1 + 16, WEEKS, 2)
    o += f'<rect x="{x0}" y="{h - 18}" width="10" height="10" rx="2" fill="#e3b04b"/>' + t(x0 + 15, h - 9, "opened", 12, INK2)
    o += f'<rect x="{x0 + 80}" y="{h - 18}" width="10" height="10" rx="2" fill="{TEAL}"/>' + t(x0 + 95, h - 9, "fixed", 12, INK2)
    o += t(x1, h - 9, "net open −28 in 12 weeks", 12, NAVY, "end", 600)
    return svg(w, h, o)

def chart_burn(w=392, h=230):
    x0, y0, x1, y1 = 34, 12, w - 8, h - 46; ymax = 100
    o = axes(x0, y0, x1, y1, ymax, 25)
    xs = [x0 + (x1 - x0) * i / 11 for i in range(12)]
    acc = [0] * 12
    for s in ["Low", "Medium", "High", "Critical"]:
        lo = acc[:]; hi = [a + v for a, v in zip(acc, burn[s])]
        Y = lambda v: y1 - (y1 - y0) * v / ymax
        pts = " ".join(f"{x:.1f},{Y(v):.1f}" for x, v in zip(xs, hi)) + " " + " ".join(f"{x:.1f},{Y(v):.1f}" for x, v in reversed(list(zip(xs, lo))))
        o += f'<polygon points="{pts}" fill="{SEV[s]}" fill-opacity=".85" stroke="#fff" stroke-width="1"/>'
        acc = hi
    o += xlabels(x0 - (x1 - x0) / 22, x1 + (x1 - x0) / 22, y1 + 16, WEEKS, 2)
    lx = x0
    for s in SEV:
        o += f'<rect x="{lx}" y="{h - 18}" width="10" height="10" rx="2" fill="{SEV[s]}"/>' + t(lx + 15, h - 9, s, 12, INK2); lx += 18 + 8 * len(s) + 12
    return svg(w, h, o)

def chart_ttf(w=392, h=230):
    x0, x1 = 78, w - 46; ymax = 80; o = ""
    for v in range(0, 81, 20):
        x = x0 + (x1 - x0) * v / ymax
        o += f'<line x1="{x:.1f}" x2="{x:.1f}" y1="8" y2="{h - 54}" stroke="{LINE}"/>' + t(x, h - 38, f"{v} d", 11, INK3, "middle")
    for i, (s, p50, p90) in enumerate(ttf):
        y = 16 + i * 40
        o += t(x0 - 10, y + 15, s, 12, INK2, "end", 600)
        o += f'<rect x="{x0}" y="{y + 3}" width="{(x1 - x0) * p90 / ymax:.1f}" height="18" rx="3" fill="{SEV[s]}" fill-opacity=".25"/>'
        o += f'<rect x="{x0}" y="{y + 3}" width="{(x1 - x0) * p50 / ymax:.1f}" height="18" rx="3" fill="{SEV[s]}"/>'
        o += t(x0 + (x1 - x0) * p90 / ymax + 6, y + 16, f"{p50:g} / {p90:g}", 11, INK2)
    o += f'<rect x="{x0}" y="{h - 18}" width="10" height="10" rx="2" fill="{NAVY}"/>' + t(x0 + 15, h - 9, "p50", 12, INK2)
    o += f'<rect x="{x0 + 52}" y="{h - 18}" width="10" height="10" rx="2" fill="{NAVY}" fill-opacity=".25"/>' + t(x0 + 67, h - 9, "p90 (days)", 12, INK2)
    o += t(w - 8, h - 9, "target [placeholder]", 12, INK3, "end")
    return svg(w, h, o)

def chart_merge(w=392, h=218):
    x0, y0, x1, y1 = 40, 12, w - 10, h - 64; lo, hi = 40, 100
    o = ""
    for v in range(40, 101, 20):
        y = y1 - (y1 - y0) * (v - lo) / (hi - lo)
        o += f'<line x1="{x0}" x2="{x1}" y1="{y:.1f}" y2="{y:.1f}" stroke="{LINE}"/>' + t(x0 - 6, y + 4, f"{v}%", 11, INK3, "end")
    xs = [x0 + (x1 - x0) * i / 11 for i in range(12)]
    for k, vals in merge.items():
        pts = " ".join(f"{x:.1f},{y1 - (y1 - y0) * (v - lo) / (hi - lo):.1f}" for x, v in zip(xs, vals))
        o += f'<polyline points="{pts}" fill="none" stroke="{FIX[k]}" stroke-width="2.4" stroke-linejoin="round"/>'
        o += f'<circle cx="{xs[-1]:.1f}" cy="{y1 - (y1 - y0) * (vals[-1] - lo) / (hi - lo):.1f}" r="3.5" fill="{FIX[k]}"/>'
    o += xlabels(x0 - (x1 - x0) / 22, x1 + (x1 - x0) / 22, y1 + 16, WEEKS, 2)
    lx, ly = x0, h - 34
    for i, k in enumerate(merge):
        if i == 2: lx, ly = x0, h - 14
        o += f'<rect x="{lx}" y="{ly - 9}" width="10" height="10" rx="2" fill="{FIX[k]}"/>' + t(lx + 15, ly, f"{k} {merge[k][-1]}%", 12, INK2); lx += 170
    return svg(w, h, o)

def spark(vals, w=96, h=26, col=TEAL):
    m = max(vals) or 1; mn = min(vals)
    pts = " ".join(f"{2 + (w - 4) * i / (len(vals) - 1):.1f},{h - 3 - (h - 6) * (v - mn) / ((m - mn) or 1):.1f}" for i, v in enumerate(vals))
    return f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}"><polyline points="{pts}" fill="none" stroke="{col}" stroke-width="2" stroke-linejoin="round"/></svg>'
def bars(vals, w=110, h=26, col="#d4570f"):
    m = max(vals) or 1; bw = w / len(vals)
    return f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}">' + "".join(
        f'<rect x="{i * bw + 1:.1f}" y="{h - 2 - (h - 4) * v / m:.1f}" width="{bw - 2:.1f}" height="{max(1.5, (h - 4) * v / m):.1f}" rx="1" fill="{col}" fill-opacity="{1 if v else .25}"/>' for i, v in enumerate(vals)) + "</svg>"

def chart_age(w=392, h=206):
    x0, x1 = 112, w - 30; m = 8; o = ""
    for i, (repo, vals) in enumerate(age):
        y = 10 + i * 34
        o += t(x0 - 10, y + 15, repo, 12, INK2, "end", 600)
        cx = x0
        for v, (lab, col) in zip(vals, AGE):
            ww = (x1 - x0) * v / m
            if v: o += f'<rect x="{cx:.1f}" y="{y + 2}" width="{ww - 1:.1f}" height="18" rx="2" fill="{col}"/>' + (t(cx + ww / 2, y + 15, v, 11, "#fff", "middle", 700) if ww > 16 else "")
            cx += ww
        o += t(cx + 6, y + 15, sum(vals), 12, NAVY, "start", 650)
    lx = x0 - 100
    for lab, col in AGE:
        o += f'<rect x="{lx}" y="{h - 18}" width="10" height="10" rx="2" fill="{col}"/>' + t(lx + 15, h - 9, lab, 12, INK2); lx += 86
    return svg(w, h, o)

# ---------------- HTML ----------------
def kpi(k, v, sub, tone=""):
    return f'<div class="kpi"><div class="k">{k}</div><div class="v {tone}">{v}</div><div class="s">{sub}</div></div>'
SAMPLE = '<span class="sdbadge" title="Every number on this tab is synthetic sample data, not computed from the recorded run"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M12 9v4"/><path d="M12 17h.01"/><circle cx="12" cy="12" r="10"/></svg>Sample data (illustrative)</span>'
def card(title, meta, body, cls=""):
    return f'<div class="card {cls}"><div class="card-h"><h2>{title}</h2><span class="meta">{meta}</span></div><div class="cb">{body}</div></div>'

qrows = "".join(f'<tr><td><b>{a}</b></td><td>{spark(tr, col=FIX.get(a, NAVY))}</td><td class="num"><b>{val}</b> <span class="mut">{lab}</span></td><td class="num">{tok}</td></tr>' for a, tr, lab, val, tok in quality)
qtable = f'<table class="tbl"><thead><tr><th>Agent</th><th>12-wk trend</th><th class="num">Now</th><th class="num">Tok / fix</th></tr></thead><tbody>{qrows}</tbody></table><div class="foot">Cost per fix = tokens × [rate per model]. Targets [placeholder].</div>'
orows = "".join(f'<tr><td><b>{r}</b><div class="mut">{tm}</div></td><td>{p}<div class="mut">{n} in 12 wk · {re_} reappeared</div></td><td>{bars(s, 84)}</td></tr>' for r, tm, p, n, re_, s in offenders)
otable = f'<table class="tbl"><thead><tr><th>Repo · team</th><th>Pattern</th><th>Per week</th></tr></thead><tbody>{orows}</tbody></table>'
erows = "".join(f'<div class="exp"><span class="sev {s.lower()}">{s}</span><div class="et"><b>{rid}</b> · {repo}<div class="mut">{why}</div></div><span class="days {"soon" if d <= 14 else ""}">{d} d</span></div>' for rid, repo, s, why, d in expiring)
lic = '<div class="licg">' + "".join(f'<div class="lic"><span>{n}</span><i style="width:{v * 22}px"></i><b>{v}</b></div>' for n, v in licence) + '</div>'
warn = "".join(f'<div class="warn {k}"><div class="wt">{a}</div><div class="wd">{b}</div></div>' for k, a, b in warnings)
MOCK = 'data-mock="1" title="Illustrative sample view: not wired to data"'

# Styles are scoped to #v-trends so the shared dashboard classes (.kpis, .kpi, .card ...) elsewhere are untouched.
css = """<style>
/* ---------- Trends tab (replay only; SAMPLE DATA). Ported from sec-agent-sdd/trends-mockup, scoped to #v-trends ---------- */
#v-trends.on{display:block;overflow:auto;padding:0 0 24px}
#v-trends .trbar{margin:16px 20px 0;background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);display:flex;align-items:center;gap:18px;padding:14px 18px;flex-wrap:wrap}
#v-trends .trbar h1{margin:0;font-size:19px;color:var(--navy);font-weight:650;letter-spacing:-.015em}
#v-trends .trbar .sub{color:var(--ink-3);font-size:13px;margin-top:2px}
#v-trends .sdbadge{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:999px;background:var(--amber-50);color:var(--amber);border:1.5px solid #e9b75a;font-weight:700;font-size:13px;letter-spacing:.01em;white-space:nowrap}
#v-trends .trbar .btn,#v-trends .trbar .seg button{white-space:nowrap}
#v-trends .sel{white-space:nowrap;height:32px;display:inline-flex;align-items:center;gap:6px;padding:0 12px;border:1px solid var(--line);border-radius:9px;font-weight:600;font-size:13px;color:var(--navy);background:#fff;cursor:pointer}
#v-trends .kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:14px;margin:14px 20px 0}
#v-trends .kpi{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);padding:12px 14px}
#v-trends .kpi .k{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--ink-3);font-weight:650}
#v-trends .kpi .v{font-size:25px;font-weight:700;color:var(--navy);margin-top:3px;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
#v-trends .kpi .v.tgood{color:var(--green)} #v-trends .kpi .v.twarn{color:var(--orange)}
#v-trends .kpi .s{font-size:12px;color:var(--ink-3);margin-top:1px;white-space:normal}
#v-trends .grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:14px 20px 0}
#v-trends .cb{padding:10px 14px 12px} #v-trends .card-h h2{font-size:12.5px} #v-trends .card-h .meta{font-size:12px}
#v-trends .tbl{width:100%;border-collapse:collapse;font-size:13px} #v-trends .tbl td .mut{font-size:11.5px}
#v-trends .tbl th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink-3);font-weight:650;padding:4px 4px 6px;border-bottom:1px solid var(--line)}
#v-trends .tbl td{padding:5px 4px;border-bottom:1px solid var(--line-2);vertical-align:middle} #v-trends .tbl .num{text-align:right;font-variant-numeric:tabular-nums} #v-trends .tbl svg{display:block}
#v-trends .mut{color:var(--ink-3);font-size:12px} #v-trends .foot{color:var(--ink-3);font-size:12px;margin-top:8px}
#v-trends .exp{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--line-2)} #v-trends .et{flex:1;font-size:13px}
#v-trends .sev{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:2px 7px;border-radius:5px}
#v-trends .sev.critical{background:var(--red-50);color:var(--red)} #v-trends .sev.high{background:var(--orange-50);color:var(--orange)} #v-trends .sev.medium{background:var(--amber-50);color:var(--amber)}
#v-trends .days{font-weight:700;font-size:13px;color:var(--ink-2);background:#eef1f3;border-radius:7px;padding:3px 9px} #v-trends .days.soon{background:var(--red-50);color:var(--red)}
#v-trends .licg{display:grid;grid-template-columns:1fr 1fr;column-gap:12px} #v-trends .lic{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:13px}
#v-trends .lic span{width:78px;color:var(--ink-2);font-weight:600} #v-trends .lic i{height:14px;border-radius:4px;background:#5b3fb5;opacity:.75} #v-trends .lic b{color:var(--navy)}
#v-trends .warn{border-left:4px solid;border-radius:8px;padding:8px 11px;margin-bottom:8px;background:#fafbfc} #v-trends .warn.crit{border-color:var(--red);background:var(--red-50)}
#v-trends .warn.high{border-color:var(--orange);background:var(--orange-50)} #v-trends .warn.med{border-color:var(--amber);background:var(--amber-50)}
#v-trends .wt{font-weight:700;font-size:13px;color:var(--navy)} #v-trends .wd{font-size:12.5px;color:var(--ink-2);margin-top:1px}
#v-trends .sechead{display:flex;align-items:center;gap:14px;margin:18px 20px 0;padding:4px 0 0} #v-trends .sechead h3{margin:0;font-size:15px;color:var(--navy);font-weight:650}
#v-trends .disclaimer{margin:14px 20px 0;color:var(--ink-3);font-size:12px}
.tabs .tab{white-space:nowrap;padding:0 12px} #cfgLabel{white-space:nowrap}
.tab .sample-pill{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#f5b544;border:1px solid rgba(245,181,68,.55);border-radius:6px;padding:1px 5px;margin-left:6px}
@media (max-width:1180px){#v-trends .kpis{grid-template-columns:repeat(3,minmax(0,1fr))} #v-trends .grid3{grid-template-columns:minmax(0,1fr)}}
</style>"""

section = f'''<section class="view" id="v-trends" aria-label="Trends (sample data)">
  <section class="trbar">
    <div><h1>Trends</h1><div class="sub">All repos · last 12 weeks · nightly rollup · read-only</div></div>
    {SAMPLE}
    <div class="sp" style="flex:1"></div>
    <span class="sel" {MOCK}>Repo: all ▾</span><span class="sel" {MOCK}>Team: all ▾</span>
    <div class="seg"><button {MOCK}>4 wk</button><button class="on" {MOCK}>12 wk</button><button {MOCK}>12 mo</button></div>
    <button class="btn" {MOCK}>Export CSV</button><button class="btn" {MOCK}>Open in Power BI</button>
  </section>
  <div class="kpis">
    {kpi("Open critical / high", f'{burn["Critical"][-1] + burn["High"][-1]}', f'was {burn["Critical"][0] + burn["High"][0]} · target [placeholder]', "tgood")}
    {kpi("Median time to fix · critical", "2.5 d", "p90 6 d · target [placeholder]")}
    {kpi("Fix PR merge rate", f"{round(sum(v[-1] for v in merge.values()) / 4)}%", "all fixers · target [placeholder]", "tgood")}
    {kpi("Triage override rate", "5%", "humans changed the decision")}
    {kpi("Tokens per merged fix", "3.4k", "cost = tokens × [rate]")}
    {kpi("Acceptances expiring ≤ 30 d", "3", "1 critical · review owner", "twarn")}
  </div>
  <div class="grid3">
    {card("Opened vs fixed", "per week", chart_opened_fixed())}
    {card("Burn-down · open findings", "by severity", chart_burn())}
    {card("Time to fix", "p50 / p90 by severity", chart_ttf())}
  </div>
  <div class="sechead"><h3>Agent quality · repeat offenders · risk view · early warning</h3>{SAMPLE}</div>
  <div class="grid3">
    {card("Fix PR merge rate per fixer", "merged ÷ opened, per week", chart_merge())}
    {card("Agent quality", "overrides · retries · tokens", qtable)}
    {card("Repeat offenders", "repo · team · pattern", otable)}
  </div>
  <div class="grid3">
    {card("Open critical / high by age", "per repo", chart_age())}
    {card("Risk acceptances expiring", "next 30 days", erows + '<div style="height:10px"></div><div class="card-h" style="padding:6px 0 6px;border:0"><h2>Licence exposure</h2><span class="meta">repos per flagged licence</span></div>' + lic)}
    {card("Early warning", "new CVEs in components in use", warn + '<div class="foot">Source: Black Duck BOM + CVE feed (ComponentExposureDaily). Alerts raise a human task; nothing is auto-merged.</div>')}
  </div>
  <div class="disclaimer">Illustrative sample. All numbers, repos, teams, packages and CVE ids on this tab are synthetic sample data (CVE-SAMPLE-*), not output of the recorded run. KPI targets are [placeholders] to agree. Controls on this tab are not wired to data.</div>
</section>'''
os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w", encoding="utf-8").write("<!-- GENERATED by scripts/build-trends-sample.py: SAMPLE DATA (illustrative). Do not edit by hand. -->\n" + css + "\n" + section + "\n")
print("wrote", OUT)
