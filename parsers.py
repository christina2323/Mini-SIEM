"""Log parsers: turn raw log lines into normalized Event objects."""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

AUTH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+")
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+")

WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)')


@dataclass
class Event:
    """Normalized event: every log source is converted to this one schema."""
    ts: datetime
    source: str            # "auth" or "web"
    host: str
    ip: str
    user: str
    action: str            # ssh_failed | ssh_success | http_request
    status: int = 0
    path: str = ""
    raw: str = ""


def parse_auth_line(line: str, year: int) -> Optional[Event]:
    m = AUTH_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    msg = m["msg"]
    f = FAILED_RE.search(msg)
    if f:
        return Event(ts, "auth", m["host"], f["ip"], f["user"], "ssh_failed", raw=line.strip())
    a = ACCEPTED_RE.search(msg)
    if a:
        return Event(ts, "auth", m["host"], a["ip"], a["user"], "ssh_success", raw=line.strip())
    return None


def parse_web_line(line: str) -> Optional[Event]:
    m = WEB_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    return Event(ts, "web", "webserver", m["ip"], "", "http_request",
                 status=int(m["status"]), path=m["path"], raw=line.strip())


def parse_file(path: str, kind: str, year: int = 2026):
    """Parse a whole log file. Returns (events, skipped_line_count)."""
    events, skipped = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            ev = parse_auth_line(line, year) if kind == "auth" else parse_web_line(line)
            if ev:
                events.append(ev)
            else:
                skipped += 1
    return events, skipped
