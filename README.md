[![Mini-SIEM Tests](https://github.com/christina2323/Mini-SIEM/actions/workflows/python-app.yml/badge.svg)](https://github.com/christina2323/Mini-SIEM/actions/workflows/python-app.yml)
# Mini SIEM - Log Monitoring and Threat Detection System

A simplified Security Information and Event Management (SIEM) system in Python
(standard library only). It collects logs, normalizes them, correlates events with
detection rules, and produces alerts and a dashboard report.

## 1. Problem Statement
Servers generate thousands of log lines a day. Attacks such as brute force, SQL injection
and scanning are buried in that noise, and nobody can read it all manually. A SIEM
centralizes logs, detects suspicious patterns automatically, and tells analysts what to act on.

## 2. Objectives
- Collect and normalize logs from multiple sources (SSH authentication, web server).
- Detect common attacks using correlation rules and time-window analysis.
- Map every alert to a MITRE ATT&CK technique and suggest a response.
- Produce a readable dashboard report and machine-readable JSON output.

## 3. Architecture
```
 auth.log ----\                                         /--> console summary
               >--> Parsers --> Normalized Events --> Rules Engine --> Alerts --> HTML dashboard
 access.log --/    (parsers.py)   (one common schema)   (rules.py)               \--> alerts.json
                                                                                   (report.py)
```
| File | Role (SIEM stage) |
|---|---|
| `parsers.py` | Collection + normalization |
| `rules.py` | Correlation / detection engine |
| `report.py` | Alerting + visualization |
| `siem.py` | Command-line controller |
| `generate_sample_logs.py` | Creates test logs with simulated attacks |
| `test_siem.py` | 15 unit tests |

## 4. Detection Rules
| Rule | Logic | Severity | MITRE ATT&CK |
|---|---|---|---|
| SSH Brute Force | 5+ failed logins from one IP in 5 min | High | T1110.001 |
| Password Spraying | One IP fails against 4+ different accounts in 10 min | High | T1110.003 |
| Possible Account Compromise | Successful login after 5+ failures from same IP | Critical | T1078 |
| Off-Hours Login | Successful login outside 07:00-20:00 | Medium | T1078 |
| Web Attacks | SQLi, XSS, path traversal patterns in URLs (after URL-decoding) | High | T1190 |
| Web Scanning | 10+ HTTP 404s from one IP in 2 min | Medium | T1595 |

**Key technique - sliding window with campaigns:** events are checked inside a moving time
window. Once a rule triggers, following events from the same attacker are merged into a
single alert, so a 30-attempt brute force produces 1 alert instead of 30 (less alert fatigue).
All thresholds are in the `CONFIG` dictionary in `rules.py`.

## 5. How to Run
Requires Python 3.8+.
```bash
python generate_sample_logs.py                    # create sample_logs/auth.log and access.log
python siem.py --auth sample_logs/auth.log --web sample_logs/access.log
# open siem_report.html in a browser; alerts.json has the raw alerts
python -m unittest -v                             # run tests
```
To analyze real logs, point `--auth` at a syslog-style `/var/log/auth.log` (SSH lines) and
`--web` at an Apache/Nginx access log in Common Log Format. Use `--year` for syslog files.

## 6. Results (sample data: 248 events -> 10 alerts)
| Simulated attack | Detected as |
|---|---|
| 30 SSH failures on root/admin | SSH Brute Force |
| 6 usernames tried by one IP | Password Spraying (+ Brute Force) |
| 8 failures then successful login | **Possible Account Compromise (Critical)** |
| Login at 23:47 | Off-Hours Login |
| sqlmap-style injection requests | SQL Injection |
| `<script>` / `onerror=` payloads | Cross-Site Scripting |
| `../../etc/passwd` | Path Traversal |
| 25 rapid 404s (Nikto) | Web Scanning |

Normal logins, occasional typos and regular web traffic produced no alerts (tested).

## 7. Testing
15 unit tests cover each parser (including malformed lines), each rule at and below its
threshold, slow attacks that stay under the radar, campaign merging, and normal traffic
(false-positive checks).

## 8. Limitations
- Detection is signature/threshold based; it can't catch unknown attack types.
- Regex web rules can be bypassed by heavy obfuscation and produce some false positives.
- Batch processing only (no real-time streaming) and no persistent storage.
- Only two log sources; no firewall, DNS or Windows event logs.
- IP-based grouping misses distributed attacks that use many IPs.

## 9. Future Improvements
- Real-time tailing of log files with email/Telegram alerts.
- IP geolocation and threat-intelligence lookups (e.g. AbuseIPDB).
- Store events in SQLite or Elasticsearch and add a Flask dashboard.
- Add more sources (firewall, Windows Event Logs) and an anomaly-detection model.
- Automated response, such as adding attacker IPs to a firewall blocklist.

## 10. Relation to Real SIEM Tools
This project mirrors the pipeline of Splunk, Elastic Security and Wazuh: ingest -> parse ->
normalize -> correlate -> alert -> visualize. Building it explains how those tools work internally.

## 11. Conclusion
The Mini SIEM shows how raw logs become actionable security intelligence through
normalization, time-window correlation and ATT&CK-mapped alerting.
