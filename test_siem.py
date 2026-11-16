import unittest
from datetime import datetime, timedelta

from parsers import Event, parse_auth_line, parse_web_line
from rules import CONFIG, run_all

T0 = datetime(2026, 11, 13, 10, 0, 0)


def ev(sec, action, ip="1.2.3.4", user="bob", status=0, path="/", hour=None):
    ts = T0 + timedelta(seconds=sec)
    if hour is not None:
        ts = ts.replace(hour=hour)
    return Event(ts, "auth" if action.startswith("ssh") else "web", "h", ip, user, action, status, path)


def rules_of(events):
    return {a.rule for a in run_all(events, CONFIG)}


class TestParsers(unittest.TestCase):
    def test_failed(self):
        line = "Nov 13 02:14:05 server1 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4444 ssh2"
        e = parse_auth_line(line, 2026)
        self.assertEqual((e.action, e.user, e.ip), ("ssh_failed", "admin", "203.0.113.5"))

    def test_accepted(self):
        line = "Nov  3 09:01:10 server1 sshd[99]: Accepted password for alice from 10.0.0.5 port 5555 ssh2"
        self.assertEqual(parse_auth_line(line, 2026).action, "ssh_success")

    def test_garbage(self):
        self.assertIsNone(parse_auth_line("not a log line", 2026))
        self.assertIsNone(parse_web_line("garbage"))

    def test_web(self):
        line = '203.0.113.9 - - [13/Nov/2026:10:00:00 +0000] "GET /a?id=1 HTTP/1.1" 404 512 "-" "x"'
        e = parse_web_line(line)
        self.assertEqual((e.ip, e.status, e.path), ("203.0.113.9", 404, "/a?id=1"))


class TestRules(unittest.TestCase):
    def test_bruteforce_detected(self):
        self.assertIn("SSH Brute Force", rules_of([ev(i * 5, "ssh_failed") for i in range(6)]))

    def test_below_threshold(self):
        self.assertEqual(rules_of([ev(i * 5, "ssh_failed") for i in range(4)]), set())

    def test_slow_attempts_not_flagged(self):
        self.assertEqual(rules_of([ev(i * 400, "ssh_failed") for i in range(6)]), set())

    def test_campaign_is_one_alert(self):
        alerts = [a for a in run_all([ev(i * 4, "ssh_failed") for i in range(40)], CONFIG)
                  if a.rule == "SSH Brute Force"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 40)

    def test_spraying(self):
        evs = [ev(i * 10, "ssh_failed", user=u) for i, u in enumerate(["a", "b", "c", "d", "e"])]
        self.assertIn("Password Spraying", rules_of(evs))

    def test_compromise_is_critical(self):
        evs = [ev(i * 10, "ssh_failed") for i in range(6)] + [ev(80, "ssh_success")]
        crit = [a for a in run_all(evs, CONFIG) if a.rule == "Possible Account Compromise"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0].severity, "Critical")

    def test_normal_login_no_alert(self):
        self.assertEqual(rules_of([ev(0, "ssh_failed"), ev(10, "ssh_success")]), set())

    def test_off_hours(self):
        self.assertIn("Off-Hours Login", rules_of([ev(0, "ssh_success", hour=3)]))
        self.assertNotIn("Off-Hours Login", rules_of([ev(0, "ssh_success", hour=11)]))

    def test_web_attacks(self):
        for path, name in [("/p?id=1%27%20OR%20%271%27%3D%271", "SQL Injection"),
                           ("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "Cross-Site Scripting"),
                           ("/d?f=../../etc/passwd", "Path Traversal")]:
            self.assertIn(f"Web Attack: {name}", rules_of([ev(0, "http_request", status=200, path=path)]))

    def test_scanner(self):
        evs = [ev(i * 2, "http_request", status=404, path=f"/x{i}") for i in range(12)]
        self.assertIn("Web Scanning / Recon", rules_of(evs))

    def test_normal_web_no_alert(self):
        self.assertEqual(rules_of([ev(i, "http_request", status=200, path="/about") for i in range(50)]), set())


if __name__ == "__main__":
    unittest.main()
