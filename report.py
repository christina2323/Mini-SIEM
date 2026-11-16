"""Report generation: console summary, JSON export, HTML dashboard."""
import json
from collections import Counter
from html import escape

COLORS = {"Critical": "#b71c1c", "High": "#e65100", "Medium": "#f9a825", "Low": "#2e7d32"}


def console_summary(alerts, total_events):
    sev = Counter(a.severity for a in alerts)
    print("=" * 60)
    print(f" MINI SIEM - {total_events} events analyzed, {len(alerts)} alerts")
    print("=" * 60)
    for s in ("Critical", "High", "Medium", "Low"):
        print(f" {s:<9}: {sev.get(s, 0)}")
    print("-" * 60)
    for a in alerts:
        print(f"[{a.severity.upper():<8}] {a.start:%Y-%m-%d %H:%M} {a.src_ip:<15} {a.rule}")
    print("=" * 60)


def write_json(alerts, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump([a.to_dict() for a in alerts], f, indent=2)


def write_html(alerts, total_events, path):
    sev = Counter(a.severity for a in alerts)
    ips = Counter(a.src_ip for a in alerts).most_common(5)
    hours = Counter(a.start.hour for a in alerts)
    peak = max(hours.values(), default=1)

    cards = "".join(
        f'<div class="card" style="border-top:5px solid {COLORS[s]}"><b>{sev.get(s, 0)}</b><span>{s}</span></div>'
        for s in COLORS)
    ip_rows = "".join(f"<tr><td>{escape(ip)}</td><td>{n}</td></tr>" for ip, n in ips)
    bars = "".join(
        f'<div class="bar" title="{h:02d}:00 - {hours.get(h, 0)} alerts">'
        f'<div style="height:{int(100 * hours.get(h, 0) / peak)}%"></div><small>{h}</small></div>'
        for h in range(24))
    rows = "".join(
        f'<tr><td><span class="sev" style="background:{COLORS[a.severity]}">{a.severity}</span></td>'
        f"<td>{a.start:%Y-%m-%d %H:%M:%S}</td><td>{escape(a.src_ip)}</td><td>{escape(a.rule)}</td>"
        f"<td>{a.count}</td><td>{escape(a.description)}</td><td>{escape(a.mitre)}</td>"
        f"<td>{escape(a.recommendation)}</td></tr>" for a in alerts)

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Mini SIEM Report</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#222}}
header{{background:#0d1b2a;color:#fff;padding:20px 30px}}
main{{padding:20px 30px}} .cards{{display:flex;gap:16px;flex-wrap:wrap}}
.card{{background:#fff;padding:16px 28px;border-radius:6px;box-shadow:0 1px 3px #0002;display:flex;flex-direction:column;align-items:center}}
.card b{{font-size:2em}} h2{{margin-top:30px}}
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px #0002;font-size:.9em}}
th,td{{padding:8px 10px;border-bottom:1px solid #e3e3e3;text-align:left;vertical-align:top}}
th{{background:#1b263b;color:#fff}} .sev{{color:#fff;padding:2px 8px;border-radius:10px;font-size:.85em}}
.chart{{display:flex;align-items:flex-end;gap:4px;height:140px;background:#fff;padding:10px;box-shadow:0 1px 3px #0002}}
.bar{{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:100%}}
.bar div{{width:100%;background:#415a77;min-height:1px}} small{{font-size:.65em}}
.wrap{{overflow-x:auto}}</style></head><body>
<header><h1>Mini SIEM - Security Report</h1><div>{total_events} events analyzed &middot; {len(alerts)} alerts</div></header>
<main><div class="cards">{cards}</div>
<h2>Alerts by hour of day</h2><div class="chart">{bars}</div>
<h2>Top source IPs</h2><table><tr><th>IP address</th><th>Alerts</th></tr>{ip_rows}</table>
<h2>All alerts</h2><div class="wrap"><table><tr><th>Severity</th><th>Time</th><th>Source IP</th><th>Rule</th>
<th>Events</th><th>Description</th><th>MITRE ATT&amp;CK</th><th>Recommended action</th></tr>{rows}</table></div>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
