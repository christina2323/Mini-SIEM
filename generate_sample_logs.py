#!/usr/bin/env python3
"""Generate realistic sample logs (normal traffic + simulated attacks) for testing the SIEM."""
import os
import random
from datetime import datetime, timedelta

rng = random.Random(42)
BASE = datetime(2026, 11, 13)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_logs")
os.makedirs(OUT, exist_ok=True)
auth, web = [], []


def at(h, m=0, s=0):
    return BASE + timedelta(hours=h, minutes=m, seconds=s)


def ssh(dt, ok, user, ip, invalid=False):
    pid, port = rng.randint(1000, 9999), rng.randint(30000, 60000)
    if ok:
        msg = f"Accepted password for {user} from {ip} port {port} ssh2"
    else:
        msg = f"Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port {port} ssh2"
    auth.append((dt, f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} server1 sshd[{pid}]: {msg}"))


def http(dt, ip, path, status, method="GET", ua="Mozilla/5.0"):
    web.append((dt, f'{ip} - - [{dt:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                    f'{status} {rng.randint(200, 9000)} "-" "{ua}"'))


# ---- Normal activity ----
users = {"alice": "10.0.0.11", "bob": "10.0.0.12", "carol": "10.0.0.13"}
for u, ip in users.items():
    for _ in range(3):
        t = at(rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
        if rng.random() < 0.4:
            ssh(t - timedelta(seconds=20), False, u, ip)          # a typo
        ssh(t, True, u, ip)
for _ in range(150):
    http(at(rng.randint(7, 22), rng.randint(0, 59), rng.randint(0, 59)),
         f"10.0.1.{rng.randint(2, 30)}", rng.choice(["/", "/about", "/products", "/contact", "/css/site.css"]), 200)

# ---- Attack 1: SSH brute force (203.0.113.50) ----
for i in range(30):
    ssh(at(2, 10, i * 4), False, rng.choice(["root", "admin"]), "203.0.113.50", invalid=True)

# ---- Attack 2: password spraying (198.51.100.23) ----
spray_users = ["admin", "root", "test", "oracle", "ubuntu", "postgres"]
for i, u in enumerate(spray_users * 2):
    ssh(at(3, 30, i * 12), False, u, "198.51.100.23", invalid=True)

# ---- Attack 3: successful compromise after guessing (192.0.2.77) ----
for i in range(8):
    ssh(at(14, 0, i * 10), False, "bob", "192.0.2.77")
ssh(at(14, 2, 5), True, "bob", "192.0.2.77")

# ---- Off-hours login ----
ssh(at(23, 47, 12), True, "carol", "10.0.0.13")

# ---- Web attacks ----
sqli = ["/products.php?id=1%27%20OR%20%271%27%3D%271", "/login.php?user=admin%27--%20",
        "/item.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users"]
for i, p in enumerate(sqli):
    http(at(11, 5, i * 7), "203.0.113.99", p, 500, ua="sqlmap/1.7")
for i, p in enumerate(["/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                       "/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E"]):
    http(at(11, 8, i * 9), "203.0.113.99", p, 200)
for i, p in enumerate(["/download?file=../../../../etc/passwd", "/view?page=..%2F..%2F..%2Fetc%2Fshadow"]):
    http(at(16, 20, i * 5), "203.0.113.100", p, 403)

# ---- Web scanner (198.51.100.200) ----
paths = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/backup.zip", "/config.php",
         "/.git/config", "/server-status", "/administrator", "/db.sql"]
for i in range(25):
    http(at(9, 40, i * 2), "198.51.100.200", paths[i % len(paths)], 404, ua="Nikto/2.5")

for name, data in (("auth.log", auth), ("access.log", web)):
    with open(os.path.join(OUT, name), "w") as f:
        f.write("\n".join(line for _, line in sorted(data)) + "\n")
print(f"Generated {len(auth)} auth lines and {len(web)} web lines in {OUT}")
