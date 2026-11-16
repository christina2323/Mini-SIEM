#!/usr/bin/env python3
"""Mini SIEM - ingest logs, run detection rules, produce reports."""
import argparse
import sys

from parsers import parse_file
from report import console_summary, write_html, write_json
from rules import run_all


def main(argv=None):
    p = argparse.ArgumentParser(description="Mini SIEM")
    p.add_argument("--auth", help="SSH auth log file")
    p.add_argument("--web", help="web server access log (Common Log Format)")
    p.add_argument("--year", type=int, default=2026, help="year for syslog timestamps")
    p.add_argument("--html", default="siem_report.html", help="HTML report path")
    p.add_argument("--json", default="alerts.json", help="JSON alert export path")
    a = p.parse_args(argv)
    if not (a.auth or a.web):
        p.error("provide at least one of --auth / --web")

    events, skipped = [], 0
    for path, kind in ((a.auth, "auth"), (a.web, "web")):
        if path:
            ev, sk = parse_file(path, kind, a.year)
            print(f"[+] {path}: {len(ev)} events parsed, {sk} lines skipped")
            events += ev
            skipped += sk

    events.sort(key=lambda e: e.ts)          # correlation across sources needs one timeline
    alerts = run_all(events)
    console_summary(alerts, len(events))
    write_json(alerts, a.json)
    write_html(alerts, len(events), a.html)
    print(f"[+] Reports written: {a.html}, {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
