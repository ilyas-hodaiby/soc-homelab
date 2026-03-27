# Scenario: SSH Brute-Force Attack

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
**Severity:** High
**Status:** Closed — True Positive
**Analyst:** Ilyas Hodaiby

---

## Scenario Summary

This scenario simulates an SSH brute-force attack launched from a Kali Linux machine against a Ubuntu endpoint monitored by a Wazuh agent. The goal was to validate the full detection pipeline — from raw login failures in `auth.log` through to a closed incident case in TheHive — and to practice the analyst workflow of detecting, investigating, and documenting an attack.

---

## Environment

| Role | Machine | IP |
|---|---|---|
| Attacker | Kali Linux (Hydra) | 192.168.56.30 |
| Target | Ubuntu 22.04 (Wazuh agent) | 192.168.56.20 |
| SIEM | Wazuh Manager + ELK | 192.168.56.10 |
| IR Platform | TheHive + Cortex | 192.168.56.11 |

---

## Attack Execution

### Tool Used

**Hydra** — a parallelised login cracker used to automate credential guessing over SSH.

### Command Run on Kali

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.20 -t 4 -V
```

**Flags explained:**
- `-l root` — target the `root` username
- `-P /usr/share/wordlists/rockyou.txt` — use the RockYou password wordlist
- `ssh://192.168.56.20` — target host and protocol
- `-t 4` — run 4 parallel threads
- `-V` — verbose output (shows each attempt)

I also ran a second pass targeting multiple usernames:

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.20 -t 4
```

Where `users.txt` contained: `root`, `admin`, `ubuntu`, `user`, `test`, `deploy`, `sysadmin`, `ilyas`

### Attack Timeline

| Time | Event |
|---|---|
| 14:02:11 | Hydra launched, first login attempt sent |
| 14:02:13 | First `Failed password` entries appear in `auth.log` |
| 14:02:45 | Wazuh rule 5763 fires — threshold exceeded (8 failures in 120s) |
| 14:03:10 | Alert indexed in Elasticsearch |
| 14:03:15 | Kibana dashboard updates — spike visible |
| 14:04:00 | ElastAlert detects 10+ events — creates case in TheHive |
| 14:05:30 | Hydra stopped — 432 total attempts logged |
| 14:07:00 | Investigation started in TheHive |
| 14:22:00 | Case closed — True Positive |

---

## What the Logs Looked Like

Raw entries from `/var/log/auth.log` on the Ubuntu target:

```
Nov 12 14:02:13 soc-agent sshd[3412]: Failed password for root from 192.168.56.30 port 54321 ssh2
Nov 12 14:02:14 soc-agent sshd[3413]: Failed password for root from 192.168.56.30 port 54322 ssh2
Nov 12 14:02:15 soc-agent sshd[3414]: Failed password for root from 192.168.56.30 port 54323 ssh2
Nov 12 14:02:16 soc-agent sshd[3415]: Failed password for invalid user admin from 192.168.56.30 port 54324 ssh2
Nov 12 14:02:17 soc-agent sshd[3416]: Failed password for invalid user ubuntu from 192.168.56.30 port 54325 ssh2
...
Nov 12 14:05:29 soc-agent sshd[3841]: Failed password for invalid user deploy from 192.168.56.30 port 54763 ssh2
```

Key observations from the raw logs:
- All failures originate from a single source IP: `192.168.56.30`
- Attempts occur at consistent, rapid intervals (~1 attempt per second)
- Multiple different usernames are tried — a classic brute-force pattern
- The keyword `invalid user` appears for non-existent accounts, indicating username enumeration

---

## Detection Chain

### 1. Wazuh Agent (Log Collection)

The Wazuh agent on the Ubuntu machine monitors `/var/log/auth.log` in real time. Every SSH failure event is parsed by Wazuh's built-in decoder for `sshd`, which extracts the source IP, username, and port from each log entry.

### 2. Wazuh Manager (Rule Matching)

Wazuh matched two rules during this attack:

| Rule ID | Description | Severity |
|---|---|---|
| 5760 | SSH authentication failure | 5 |
| 5763 | Multiple SSH authentication failures (same source) | 10 |

Rule 5763 fires when more than 8 authentication failures occur from the same source IP within a 120-second window. This threshold was met within the first 45 seconds of the attack.

### 3. ELK Stack (Indexing and Visualisation)

The Wazuh alert for rule 5763 was forwarded to Logstash, enriched with GeoIP metadata (in this case, the source resolved to a private IP range since it's a lab), and indexed into Elasticsearch under `wazuh-alerts-4.x-2024.11.12`.

The Kibana dashboard showed a clear spike in the `authentication_failure` event count, with all events attributed to a single source IP.

### 4. ElastAlert (Automated Notification)

My ElastAlert rule checked the `wazuh-alerts-*` index every 2 minutes for spikes in SSH failure events. When it found 10+ matching events within a 5-minute window, it fired and used TheHive's API to create a new case with the alert summary pre-filled.

### 5. TheHive (Incident Case)

The case arrived in TheHive with the following pre-populated fields:
- **Title:** SSH Brute Force Detected — 192.168.56.30
- **Severity:** High
- **Source:** ElastAlert
- **Observable:** Source IP `192.168.56.30`
- **Tags:** `brute-force`, `ssh`, `T1110.001`

---

## Investigation Steps (What I Did as the Analyst)

1. **Reviewed the alert** in Kibana — confirmed spike pattern, identified source IP and targeted usernames
2. **Ran Cortex analyser** on source IP `192.168.56.30` — AbuseIPDB lookup (returned no hits since it's a private IP — expected in lab)
3. **Cross-referenced in MISP** — checked if IP appeared in any loaded threat feeds
4. **Reviewed `auth.log` directly** on the agent via Wazuh's log viewer — confirmed 432 failed attempts, no successful logins
5. **Checked for lateral movement** — reviewed process creation and network connection logs on the target — no further suspicious activity
6. **Confirmed no successful authentication** — no `Accepted password` or `Accepted publickey` entries in the log window
7. **Documented IOCs** in TheHive case
8. **Classified case** as True Positive — brute-force attack, no compromise
9. **Closed case** with remediation note: source IP blocked at host firewall with `ufw deny from 192.168.56.30`

---

## Extracted IOCs

| Type | Value | Notes |
|---|---|---|
| Source IP | 192.168.56.30 | Attacker machine — Kali Linux |
| Target IP | 192.168.56.20 | Ubuntu monitored endpoint |
| Target port | 22 (SSH) | |
| Usernames attempted | root, admin, ubuntu, user, test, deploy, sysadmin, ilyas | 8 distinct usernames |
| Attack tool signature | Hydra-style rapid sequential auth attempts | ~1 attempt/sec per thread |
| First event | 2024-11-12 14:02:13 UTC | |
| Last event | 2024-11-12 14:05:29 UTC | |
| Total attempts | 432 | |
| Successful logins | 0 | No compromise occurred |

---

## Outcome

The attack was fully detected, investigated, and closed as a true positive with no successful compromise. The detection pipeline performed as expected — Wazuh fired within 45 seconds of the attack starting, and the full pipeline from raw log to TheHive case took under 2 minutes.

📄 See [detection-analysis.md](detection-analysis.md) for a deeper technical breakdown of the detection logic.
📄 See [../../reports/incident-report-brute-force.md](../../reports/incident-report-brute-force.md) for the formal incident report.
