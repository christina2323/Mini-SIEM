"""Detection / correlation rules."""
import re
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import unquote_plus

CONFIG = {
    "bf_threshold": 5, "bf_window": 300,            # brute force: 5 fails / 5 min
    "spray_users": 4, "spray_window": 600,          # spraying: 4 users / 10 min
    "compromise_failures": 5, "compromise_window": 600,
    "scan_threshold": 10, "scan_window": 120,       # 10 x 404 / 2 min
    "work_start": 7, "work_end": 20,                # normal login hours
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

WEB_PATTERNS = {
    "SQL Injection": re.compile(
        r"(\bunion\b.+\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|'\s*or\s*'"
        r"|--\s|;\s*drop\s+table|sleep\(\d+\)|information_schema)", re.I),
    "Cross-Site Scripting": re.compile(
        r"(<script|javascript:|onerror\s*=|onload\s*=)", re.I),
    "Path Traversal": re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)", re.I),
}


@dataclass
class Alert:
    rule: str
    severity: str
    src_ip: str
    start: datetime
    end: datetime
    count: int
    description: str
    mitre: str
    recommendation: str
    user: str = ""

    def to_dict(self):
        d = asdict(self)
        d["start"], d["end"] = self.start.isoformat(), self.end.isoformat()
        return d


def _group_by_ip(events):
    groups = defaultdict(list)
    for e in sorted(events, key=lambda e: e.ts):
        groups[e.ip].append(e)
    return groups


def find_bursts(events, window, triggered):
    """Sliding-window detector. `events` must be time-sorted.
    When triggered(window_events) is true, a 'campaign' starts and keeps
    absorbing events until there is a gap longer than `window`. One alert
    per campaign instead of one per event (reduces alert fatigue)."""
    win, campaign = deque(), None
    for ev in events:
        if campaign is not None:
            if (ev.ts - campaign[-1].ts).total_seconds() <= window:
                campaign.append(ev)
                continue
            yield campaign
            campaign = None
            win.clear()
        win.append(ev)
        while (ev.ts - win[0].ts).total_seconds() > window:
            win.popleft()
        if triggered(win):
            campaign = list(win)
    if campaign:
        yield campaign


def rule_ssh_bruteforce(events, cfg):
    fails = [e for e in events if e.action == "ssh_failed"]
    for ip, evs in _group_by_ip(fails).items():
        for c in find_bursts(evs, cfg["bf_window"], lambda w: len(w) >= cfg["bf_threshold"]):
            users = sorted({e.user for e in c})
            yield Alert("SSH Brute Force", "High", ip, c[0].ts, c[-1].ts, len(c),
                        f"{len(c)} failed SSH logins (accounts tried: {', '.join(users[:5])}).",
                        "T1110.001 Password Guessing",
                        "Block the IP, enforce key-based auth, install fail2ban.")


def rule_password_spraying(events, cfg):
    fails = [e for e in events if e.action == "ssh_failed"]
    for ip, evs in _group_by_ip(fails).items():
        for c in find_bursts(evs, cfg["spray_window"],
                             lambda w: len({e.user for e in w}) >= cfg["spray_users"]):
            n = len({e.user for e in c})
            yield Alert("Password Spraying", "High", ip, c[0].ts, c[-1].ts, len(c),
                        f"One IP tried {n} different accounts ({len(c)} attempts).",
                        "T1110.003 Password Spraying",
                        "Block the IP, enable account lockout and MFA, review targeted accounts.")


def rule_success_after_failures(events, cfg):
    auth = [e for e in events if e.action in ("ssh_failed", "ssh_success")]
    for ip, evs in _group_by_ip(auth).items():
        recent = deque()
        for e in evs:
            while recent and (e.ts - recent[0].ts).total_seconds() > cfg["compromise_window"]:
                recent.popleft()
            if e.action == "ssh_failed":
                recent.append(e)
            elif len(recent) >= cfg["compromise_failures"]:
                yield Alert("Possible Account Compromise", "Critical", ip, recent[0].ts, e.ts,
                            len(recent) + 1,
                            f"Successful login for '{e.user}' right after {len(recent)} failures.",
                            "T1078 Valid Accounts",
                            "Disable the account, force password reset, kill active sessions, investigate.",
                            user=e.user)
                recent.clear()


def rule_off_hours_login(events, cfg):
    for e in events:
        if e.action == "ssh_success" and not (cfg["work_start"] <= e.ts.hour < cfg["work_end"]):
            yield Alert("Off-Hours Login", "Medium", e.ip, e.ts, e.ts, 1,
                        f"User '{e.user}' logged in at {e.ts:%H:%M}, outside normal hours.",
                        "T1078 Valid Accounts",
                        "Confirm with the user that this login was legitimate.", user=e.user)


def rule_web_attacks(events, cfg):
    hits = defaultdict(list)
    for e in events:
        if e.action != "http_request":
            continue
        decoded = unquote_plus(e.path)
        for name, rx in WEB_PATTERNS.items():
            if rx.search(decoded):
                hits[(e.ip, name)].append(e)
    for (ip, name), evs in hits.items():
        yield Alert(f"Web Attack: {name}", "High", ip, evs[0].ts, evs[-1].ts, len(evs),
                    f"{len(evs)} request(s) containing {name} payloads. Example: {unquote_plus(evs[0].path)[:80]}",
                    "T1190 Exploit Public-Facing Application",
                    "Block the IP, enable a WAF, use parameterized queries and input validation.")


def rule_web_scanning(events, cfg):
    notfound = [e for e in events if e.action == "http_request" and e.status == 404]
    for ip, evs in _group_by_ip(notfound).items():
        for c in find_bursts(evs, cfg["scan_window"], lambda w: len(w) >= cfg["scan_threshold"]):
            yield Alert("Web Scanning / Recon", "Medium", ip, c[0].ts, c[-1].ts, len(c),
                        f"{len(c)} requests to non-existent pages (probing for hidden files).",
                        "T1595 Active Scanning",
                        "Rate-limit or block the IP and make sure sensitive files are not exposed.")


ALL_RULES = [rule_ssh_bruteforce, rule_password_spraying, rule_success_after_failures,
             rule_off_hours_login, rule_web_attacks, rule_web_scanning]


def run_all(events, cfg=None):
    cfg = cfg or CONFIG
    alerts = [a for rule in ALL_RULES for a in rule(events, cfg)]
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.start))
