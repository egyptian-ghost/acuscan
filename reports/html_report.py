#!/usr/bin/env python3
"""Self-contained HTML report with filters, sort, and evidence viewer."""
import json
from collections import Counter
from datetime import datetime

from core.config import VERSION


def _esc(s):
    if not s:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&#39;"))


def write_html_report(filepath, targets, findings):
    sev_counts = Counter(f.severity for f in findings)
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    rows = []
    for f in findings:
        rows.append({
            "id": f.id,
            "name": _esc(f.name),
            "severity": f.severity,
            "url": _esc(f.url),
            "parameter": _esc(getattr(f, "parameter", "")),
            "detail": _esc(f.detail),
            "evidence": _esc(getattr(f, "evidence", "")),
            "cve": _esc(getattr(f, "cve", "")),
            "cwe": _esc(getattr(f, "cwe", "")),
            "payload": _esc(getattr(f, "payload", "")),
            "confidence": getattr(f, "confidence", 0),
            "verified": bool(getattr(f, "verified", False)),
            "category": _esc(getattr(f, "category", "")),
            "check_name": _esc(getattr(f, "check_name", "")),
            "verification_methods": getattr(f, "verification_methods", []),
            "extracted_info": getattr(f, "extracted_info", {}),
            "request": (f.request or "")[:5000] if hasattr(f, "request") else "",
            "response": (f.response or "")[:5000] if hasattr(f, "response") else "",
            "timestamp": f.timestamp,
        })

    rows_json = json.dumps(rows, ensure_ascii=False)
    targets_html = ', '.join(_esc(t) for t in targets)
    total = len(findings)

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AcuScan Report - """ + scan_time + """</title>
<style>
:root{--bg:#0a0f1c;--bg2:#0f172a;--bg3:#1e293b;--bg4:#334155;--fg:#f1f5f9;
--fg2:#cbd5e1;--fg3:#94a3b8;--fg4:#64748b;--accent:#38bdf8;--border:#1e293b;
--border2:#334155;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#2563eb;
--info:#6b7280;--ok:#10b981;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--fg);font-family:system-ui,sans-serif;font-size:14px;}
.container{max-width:1600px;margin:0 auto;padding:20px;}
header{background:linear-gradient(135deg,#0f172a,#1e3a5f);border:1px solid var(--border2);
border-radius:16px;padding:32px;margin-bottom:24px;}
header h1{color:var(--accent);font-size:30px;margin-bottom:12px;}
header .meta{color:var(--fg3);font-size:13px;line-height:1.8;}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
gap:16px;margin-bottom:24px;}
.stat{background:var(--bg2);border:1px solid var(--border2);border-radius:12px;
padding:20px;}
.stat .num{font-size:36px;font-weight:800;margin-bottom:6px;letter-spacing:-1px;}
.stat .label{font-size:12px;color:var(--fg3);text-transform:uppercase;
letter-spacing:1px;font-weight:600;}
.stat.total .num{color:var(--accent);}
.stat.crit .num{color:var(--crit);}
.stat.high .num{color:var(--high);}
.stat.med .num{color:var(--med);}
.stat.low .num{color:var(--low);}
.stat.info .num{color:var(--info);}
.stat.verified .num{color:var(--ok);}
.controls{background:var(--bg2);border:1px solid var(--border2);
border-radius:12px;padding:16px;margin-bottom:20px;display:flex;gap:12px;
flex-wrap:wrap;align-items:center;}
.controls input,.controls select{background:var(--bg);border:1px solid var(--border2);
color:var(--fg);border-radius:8px;padding:9px 14px;font-size:13px;outline:none;}
.controls input[type=text]{width:320px;}
table{width:100%;border-collapse:collapse;background:var(--bg2);
border-radius:12px;overflow:hidden;border:1px solid var(--border2);}
thead{background:var(--bg3);}
th{padding:14px 12px;text-align:left;font-size:11px;text-transform:uppercase;
color:var(--fg3);font-weight:700;letter-spacing:.5px;white-space:nowrap;
cursor:pointer;}
th:hover{color:var(--accent);}
td{padding:12px;border-top:1px solid var(--border);
font-size:13px;vertical-align:top;max-width:400px;word-break:break-word;}
tr:hover td{background:rgba(56,189,248,.05);}
.sev-badge{display:inline-block;padding:4px 12px;border-radius:14px;
font-size:11px;font-weight:800;text-transform:uppercase;color:#fff;
min-width:75px;text-align:center;letter-spacing:.5px;}
.sev-critical{background:var(--crit);}
.sev-high{background:var(--high);}
.sev-medium{background:var(--med);}
.sev-low{background:var(--low);}
.sev-info{background:var(--info);}
.url-cell{font-family:monospace;font-size:11px;color:var(--accent);
word-break:break-all;}
.verified-badge{display:inline-block;padding:3px 10px;border-radius:10px;
font-size:10px;font-weight:700;background:var(--ok);color:#fff;}
.unverified-badge{display:inline-block;padding:3px 10px;border-radius:10px;
font-size:10px;font-weight:700;background:var(--fg4);color:#fff;}
.conf-badge{display:inline-block;padding:3px 10px;border-radius:10px;
font-size:11px;font-weight:700;background:var(--bg4);color:var(--fg);}
.conf-high{background:var(--ok);color:#fff;}
.conf-med{background:var(--med);color:#fff;}
.conf-low{background:var(--fg4);color:#fff;}
.expand-btn{background:none;border:1px solid var(--border2);color:var(--accent);
cursor:pointer;border-radius:6px;padding:3px 10px;font-size:11px;font-weight:600;}
.expand-btn:hover{background:var(--bg3);}
.row-detail{display:none;background:var(--bg);}
.row-detail td{padding:20px 24px;line-height:1.8;max-width:none;}
.field{display:flex;gap:14px;margin-bottom:8px;}
.field-label{color:var(--fg3);min-width:140px;font-weight:600;font-size:12px;
text-transform:uppercase;letter-spacing:.5px;}
.field-value{color:var(--fg);font-family:monospace;font-size:12px;
word-break:break-all;flex:1;}
.evidence-block{background:#000;color:#4ade80;padding:12px 16px;
border-radius:8px;font-family:monospace;font-size:12px;margin:8px 0;
max-height:250px;overflow:auto;border:1px solid var(--border2);}
.http-tabs{display:flex;gap:4px;border-bottom:1px solid var(--border2);
margin:12px 0;}
.http-tab{padding:8px 16px;background:transparent;border:none;color:var(--fg3);
cursor:pointer;font-size:12px;border-bottom:2px solid transparent;
font-weight:600;}
.http-tab.active{color:var(--accent);border-bottom-color:var(--accent);}
.http-view{background:#000;color:#94a3b8;padding:14px;border-radius:8px;
font-family:monospace;font-size:11px;max-height:400px;overflow:auto;
white-space:pre-wrap;line-height:1.6;}
footer{text-align:center;color:var(--fg3);font-size:12px;margin-top:24px;padding:20px;}
</style>
</head>
<body>
<div class="container">
<header>
<h1>&#128270; AcuScan Report</h1>
<div class="meta">
<b>Scanner:</b> AcuScan v""" + VERSION + """ &nbsp;|&nbsp;
<b>Date:</b> """ + scan_time + """ &nbsp;|&nbsp;
<b>Targets:</b> """ + targets_html + """ &nbsp;|&nbsp;
<b>Findings:</b> """ + str(total) + """
</div>
</header>
<div class="stats">
<div class="stat total"><div class="num">""" + str(total) + """</div>
<div class="label">Total</div></div>
<div class="stat verified"><div class="num">""" + str(
    sum(1 for r in rows if r["verified"])) + """</div>
<div class="label">Verified</div></div>
<div class="stat crit"><div class="num">""" + str(
    sev_counts.get("critical", 0)) + """</div>
<div class="label">Critical</div></div>
<div class="stat high"><div class="num">""" + str(
    sev_counts.get("high", 0)) + """</div>
<div class="label">High</div></div>
<div class="stat med"><div class="num">""" + str(
    sev_counts.get("medium", 0)) + """</div>
<div class="label">Medium</div></div>
<div class="stat low"><div class="num">""" + str(
    sev_counts.get("low", 0)) + """</div>
<div class="label">Low</div></div>
<div class="stat info"><div class="num">""" + str(
    sev_counts.get("info", 0)) + """</div>
<div class="label">Info</div></div>
</div>
<div class="controls">
<input type="text" id="search" placeholder="Search..." oninput="render()">
<select id="sevFilter" onchange="render()">
<option value="">All severities</option>
<option>critical</option><option>high</option><option>medium</option>
<option>low</option><option>info</option>
</select>
<select id="verifiedFilter" onchange="render()">
<option value="">All findings</option>
<option value="1">Verified only</option>
<option value="0">Unverified only</option>
</select>
<span id="count" style="color:var(--fg3);margin-left:auto;"></span>
</div>
<table>
<thead><tr>
<th onclick="sortBy(0)">#</th>
<th onclick="sortBy(1)">Severity</th>
<th onclick="sortBy(2)">Name</th>
<th onclick="sortBy(3)">URL</th>
<th onclick="sortBy(4)">Param</th>
<th onclick="sortBy(5)">Conf</th>
<th>Verified</th>
<th>+</th>
</tr></thead>
<tbody id="tbody"></tbody>
</table>
<footer>Generated by AcuScan v""" + VERSION + """ - """ + scan_time + """</footer>
</div>
<script>
const DATA = """ + rows_json + """;
const SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4};
let sortCol = 1, sortAsc = true;

function esc(s){if(!s)return '';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function confClass(c){if(c>=0.85)return 'conf-high';if(c>=0.7)return 'conf-med';return 'conf-low';}

function sortBy(c){
  if(sortCol===c) sortAsc=!sortAsc; else {sortCol=c; sortAsc=true;}
  render();
}

function getSortVal(r, c){
  switch(c){
    case 0: return r.id;
    case 1: return SEV_ORDER[r.severity]||9;
    case 2: return r.name.toLowerCase();
    case 3: return r.url.toLowerCase();
    case 4: return (r.parameter||'').toLowerCase();
    case 5: return r.confidence||0;
  }
  return '';
}

function render(){
  const q = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  const vf = document.getElementById('verifiedFilter').value;

  let rows = DATA.filter(r => {
    if(sev && r.severity !== sev) return false;
    if(vf === '1' && !r.verified) return false;
    if(vf === '0' && r.verified) return false;
    if(q){
      const hay = (r.name+' '+r.url+' '+(r.detail||'')+' '+(r.cve||'')+' '+(r.parameter||'')).toLowerCase();
      if(hay.indexOf(q) === -1) return false;
    }
    return true;
  });

  rows.sort((a,b) => {
    const va = getSortVal(a, sortCol), vb = getSortVal(b, sortCol);
    if(typeof va === 'number') return sortAsc ? va-vb : vb-va;
    return sortAsc ? String(va).localeCompare(String(vb))
                   : String(vb).localeCompare(String(va));
  });

  document.getElementById('count').textContent = rows.length + ' / ' + DATA.length;
  const tbody = document.getElementById('tbody');
  const frags = [];
  rows.forEach((r, i) => {
    const conf = r.confidence ? Math.round(r.confidence*100)+'%' : '-';
    frags.push('<tr>');
    frags.push('<td>'+(i+1)+'</td>');
    frags.push('<td><span class="sev-badge sev-'+r.severity+'">'+r.severity+'</span></td>');
    frags.push('<td><strong>'+esc(r.name)+'</strong></td>');
    frags.push('<td class="url-cell">'+esc(r.url)+'</td>');
    frags.push('<td>'+(r.parameter?`<code>${esc(r.parameter)}</code>`:'-')+'</td>');
    frags.push('<td><span class="conf-badge '+confClass(r.confidence)+'">'+conf+'</span></td>');
    frags.push('<td>'+(r.verified?'<span class="verified-badge">VERIFIED</span>':'<span class="unverified-badge">NO</span>')+'</td>');
    frags.push('<td><button class="expand-btn" onclick="toggleDetail('+r.id+',this)">+</button></td>');
    frags.push('</tr>');
    frags.push('<tr class="row-detail" id="d-'+r.id+'"><td colspan="8"><div>');
    [['Name',r.name],['Severity',r.severity],['URL',r.url],['Parameter',r.parameter],
     ['Confidence',r.confidence?Math.round(r.confidence*100)+'%':''],
     ['Category',r.category],['Check',r.check_name],
     ['Verified by',(r.verification_methods||[]).join(', ')],
     ['Detail',r.detail],['Payload',r.payload],['CVE',r.cve],['CWE',r.cwe],
     ['Time',r.timestamp]
    ].forEach(f => {
      if(f[1]) frags.push('<div class="field"><span class="field-label">'+f[0]+':</span><span class="field-value">'+esc(f[1])+'</span></div>');
    });
    if(r.evidence) frags.push('<div class="field"><span class="field-label">Evidence:</span></div><div class="evidence-block">'+esc(r.evidence)+'</div>');
    if(r.extracted_info && Object.keys(r.extracted_info).length){
      frags.push('<div class="field"><span class="field-label">Extracted:</span></div><div class="evidence-block">'+esc(JSON.stringify(r.extracted_info, null, 2))+'</div>');
    }
    if(r.request){
      frags.push('<div class="field"><span class="field-label">HTTP Request:</span></div><div class="http-view">'+esc(r.request)+'</div>');
    }
    if(r.response){
      frags.push('<div class="field"><span class="field-label">HTTP Response:</span></div><div class="http-view">'+esc(r.response)+'</div>');
    }
    frags.push('</div></td></tr>');
  });
  tbody.innerHTML = frags.join('');
}

function toggleDetail(id, btn){
  const r = document.getElementById('d-'+id);
  if(r.style.display === 'table-row'){r.style.display='none';btn.textContent='+';}
  else {r.style.display='table-row';btn.textContent='-';}
}

render();
</script>
</body>
</html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)