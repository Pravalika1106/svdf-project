# make_report.py
import json, webbrowser, os, html
from pathlib import Path

IN = Path("reports/report.json")
OUT = Path("reports/report.html")

if not IN.exists():
    print("report.json not found. Run the scanner first (py run.py).")
    raise SystemExit(1)

data = json.loads(IN.read_text())

# simple helpers
def esc(s):
    return html.escape(str(s)) if s is not None else ""

# build html
title = f"SVDF Report — {esc(data.get('target',''))}"
summary = {
    "generated_at": data.get("generated_at","-"),
    "target": data.get("target","-"),
    "static_findings": len(data.get("static_findings",[])),
    "fuzzer_crashes": len(data.get("fuzzer_crashes",[]))
}

css = """
body{background:#0b1220;color:#e6eef8;font-family:Inter,Segoe UI,Arial;padding:24px}
.container{max-width:980px;margin:0 auto}
.header{display:flex;justify-content:space-between;align-items:center}
.card{background:#081028;padding:14px;border-radius:10px;margin-top:12px;box-shadow:0 6px 18px rgba(2,6,23,0.6)}
h1{margin:0 0 8px 0}
.small{color:#9fb0d6;font-size:13px}
.table{width:100%;border-collapse:collapse;margin-top:8px}
.table th{background:#07102a;padding:8px;text-align:left;color:#9fb0d6;font-weight:600}
.table td{padding:8px;border-top:1px solid rgba(255,255,255,0.03)}
.badge{display:inline-block;padding:5px 8px;border-radius:6px;font-weight:600;font-size:12px}
.cr{background:#07102a;padding:12px;border-radius:8px;margin-top:8px}
.code{background:#02111f;padding:8px;border-radius:6px;font-family:Consolas,monospace;font-size:13px;color:#cfe8ff}
.footer{margin-top:20px;color:#9fb0d6;font-size:13px}
"""

def severity_color(s):
    if s=="CRITICAL": return "#b91c1c"
    if s=="HIGH": return "#f97316"
    if s=="MEDIUM": return "#f59e0b"
    return "#10b981"

html_parts = []
html_parts.append(f"<!doctype html><html><head><meta charset='utf-8'><title>{esc(title)}</title><style>{css}</style></head><body><div class='container'>")
html_parts.append("<div class='header'><div><h1>SVDF Scan Report</h1><div class='small'>Simple human-friendly report generated from report.json</div></div>")
html_parts.append(f"<div style='text-align:right'><div class='small'>Target</div><div style='font-weight:700'>{esc(summary['target'])}</div><div class='small' style='margin-top:6px'>Generated: {esc(summary['generated_at'])}</div></div></div>")

# summary cards
html_parts.append("<div style='display:flex;gap:12px;margin-top:16px'><div class='card' style='flex:1'><div class='small'>Static Findings</div><div style='font-weight:700;font-size:22px'>{}</div></div>".format(summary["static_findings"]))
html_parts.append("<div class='card' style='width:160px;text-align:center'><div class='small'>Fuzzer Crashes</div><div style='font-weight:700;font-size:22px'>{}</div></div></div>".format(summary["fuzzer_crashes"]))

# Static findings table
html_parts.append("<div class='card'><h3>Static Findings</h3>")
if not data.get("static_findings"):
    html_parts.append("<div class='small'>No static findings.</div>")
else:
    html_parts.append("<table class='table'><thead><tr><th>ID</th><th>File:Line</th><th>Description</th><th>Snippet</th><th>Fix</th><th>Severity</th></tr></thead><tbody>")
    for f in data.get("static_findings",[]):
        html_parts.append("<tr>")
        html_parts.append(f"<td>{esc(f.get('id','-'))}</td>")
        html_parts.append(f"<td>{esc(f.get('file','-'))}:{esc(f.get('line','-'))}</td>")
        html_parts.append(f"<td>{esc(f.get('message','-'))}</td>")
        html_parts.append(f"<td><div class='code'>{esc(f.get('snippet',''))}</div></td>")
        html_parts.append(f"<td>{esc(f.get('suggested_fix','-'))}</td>")
        sev = esc(f.get('severity','-'))
        color = severity_color(sev)
        html_parts.append(f"<td><span class='badge' style='background:{color}'>{sev}</span></td>")
        html_parts.append("</tr>")
    html_parts.append("</tbody></table>")
html_parts.append("</div>")  # end static card

# Sanitizer outputs
html_parts.append("<div class='card'><h3>Sanitizer / Compile Info</h3>")
for k,v in data.get("sanitizer",{}).items():
    html_parts.append(f"<div style='Margin-top:6px'><strong>{esc(k)}</strong>")
    html_parts.append(f"<div class='small'>compile_returncode: {esc(v.get('compile_returncode'))}</div>")
    if v.get("compile_stderr"):
        html_parts.append(f"<div class='code'>{esc(v.get('compile_stderr')[:4000])}</div>")
    html_parts.append("</div>")
html_parts.append("</div>")  # end sanitizer

# Fuzzer crashes
html_parts.append("<div class='card'><h3>Fuzzer Crashes</h3>")
if not data.get("fuzzer_crashes"):
    html_parts.append("<div class='small'>No crashes found.</div>")
else:
    for c in data.get("fuzzer_crashes",[]):
        html_parts.append("<div class='cr'>")
        html_parts.append(f"<div><strong>Input file:</strong> {esc(c.get('input'))}</div>")
        if c.get("log") and Path(c.get("log")).exists():
            log_text = Path(c.get("log")).read_text(errors='ignore')[:10000]
            html_parts.append(f"<div style='margin-top:6px' class='code'>{esc(log_text)}</div>")
        else:
            html_parts.append(f"<div class='small'>Log file not found or missing.</div>")
        html_parts.append(f"<div style='margin-top:8px'><strong>Return code:</strong> {esc(c.get('rc'))}</div>")
        html_parts.append("</div>")
html_parts.append("</div>")  # end fuzzer

html_parts.append("<div class='footer'>Generated by SVDF — static analyzer + sanitizer + fuzzer. Keep findings in git, fix high/critical issues first.</div>")
html_parts.append("</div></body></html>")

OUT.write_text("".join(html_parts), encoding="utf-8")
print(f"Saved HTML report to {OUT.resolve()}")
# open in default browser (Windows)
try:
    webbrowser.open(OUT.resolve().as_uri())
except Exception:
    pass
