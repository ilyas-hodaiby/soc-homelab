# Incident Report — SSH Brute-Force Attack

 | Field | Value |
 |---|---|
 | **Report ID** | INC-2024-001 |
 | **Date of Incident** | 2024-11-12 |
 | **Date of Report** | 2024-11-12 |
 | **Analyst** | Ilyas Hodaiby |
 | **Severity** | High |
 | **Classification** | True Positive |
 | **Status** | Closed |
 | **MITRE ATT&CK** | T1110.001 — Brute Force: Password Guessing |

---

## Executive Summary

On 12 November 2024, a sustained SSH brute-force attack was detected against the Ubuntu endpoint `soc-agent` (192.168.56.20). The attack originated from `192.168.56.30` (Kali Linux — attacker machine) and involved 432 automated login attempts targeting 8 different usernames over a period of approximately 3.5 minutes.

The attack was detected by Wazuh rule 5763 within 45 seconds of the first attempt. The full detection pipeline — from raw log entry to a case in TheHive — completed in under 2 minutes. Investigation confirmed that no authentication attempt was successful. The target system was not compromised. The incident was closed as a true positive with no impact to system integrity or data.

---

## 1. Incident Timeline

| Time (UTC) | Event |
|---|---|
| 14:02:11 | Hydra launched on attacker machine — first SSH connection attempt made |
| 14:02:13 | First `Failed password` entry appears in `/var/log/auth.log` on soc-agent |
| 14:02:16 | First `invalid user` entry logged — username enumeration begins |
| 14:02:45 | Wazuh rule 5763 fires — 8 failures from same IP within 60-second window |
| 14:02:47 | Custom rule 100001 fires — lower threshold triggered earlier (5 failures/60s) |
| 14:03:10 | Wazuh alert forwarded to Logstash → indexed in Elasticsearch |
| 14:03:15 | Kibana dashboard updates — spike in `authentication_failure` events visible |
| 14:04:00 | ElastAlert detects 10+ events in 5-minute window — TheHive case auto-created |
| 14:05:29 | Last login attempt recorded — Hydra terminated |
| 14:05:30 | Attack ends — total of 432 failed attempts logged |
| 14:07:00 | Analyst begins investigation in TheHive |
| 14:09:00 | Cortex AbuseIPDB analyser run on source IP — no external reputation hit (lab IP) |
| 14:11:00 | MISP cross-reference completed — IP not found in threat feeds |
| 14:14:00 | Auth.log reviewed — confirmed zero successful logins |
| 14:17:00 | Process and connection logs reviewed — no indicators of post-exploitation |
| 14:22:00 | Case closed — True Positive, No Compromise |

---

## 2. Attack Description

### Attack Method

The attacker used **Hydra**, a parallelised login cracker, to automate SSH authentication attempts against the target. Hydra was configured with 4 parallel threads (`-t 4`) and iterated through passwords in the RockYou wordlist while rotating through a list of 8 common usernames.

The attack method is classified as **Credential Brute Forcing (T1110.001)**. The username rotation behaviour also exhibits characteristics of **Password Spraying (T1110.003)**, where common passwords are attempted across many usernames rather than exhausting all passwords against a single account.

### Attacker Intent

Based on the observed behaviour, the attacker's objective was to obtain valid SSH credentials that could be used to gain interactive shell access to the target machine. SSH access would allow execution of arbitrary commands, privilege escalation attempts, and lateral movement within the network.

### Why It Failed

The attack did not succeed because none of the usernames targeted had a password present in the RockYou wordlist. The accounts either used strong passwords or did not exist on the system (indicated by the `invalid user` entries). The attack was stopped before it could exhaust a meaningful portion of the wordlist.

---

## 3. Affected Systems

| System | IP | Role | Impact |
|---|---|---|---|
| soc-agent | 192.168.56.20 | Ubuntu endpoint — attack target | No compromise — failed authentication only |
| soc-manager | 192.168.56.10 | Wazuh + ELK — detection platform | Not targeted — unaffected |
| soc-ir | 192.168.56.11 | TheHive + Cortex + MISP | Not targeted — unaffected |

---

## 4. Indicators of Compromise (IOCs)

| IOC Type | Value | Context |
|---|---|---|
| Source IP | 192.168.56.30 | Attacker machine — all attack traffic originated here |
| Target IP | 192.168.56.20 | Monitored Ubuntu endpoint |
| Target port | TCP/22 | SSH service |
| Attack tool | Hydra (inferred from pattern) | Automated credential guessing |
| Usernames attempted | root, admin, ubuntu, user, test, deploy, sysadmin, ilyas | 8 accounts targeted |
| First attempt timestamp | 2024-11-12 14:02:11 UTC | |
| Last attempt timestamp | 2024-11-12 14:05:29 UTC | |
| Total failed attempts | 432 | |
| Successful authentications | 0 | No breach |

---

## 5. Detection Details

### Alert triggered

**Wazuh Rule 5763** — Multiple SSH authentication failures from the same source IP
- Severity: Level 10 (High)
- Threshold: 8 failures from same source IP within 120 seconds
- Triggered at: 14:02:45 UTC (34 seconds after first attempt)

**Custom Rule 100001** — Rapid SSH authentication failures (custom)
- Severity: Level 12 (Critical)
- Threshold: 5 failures from same source IP within 60 seconds
- Triggered at: 14:02:47 UTC

**ElastAlert rule: ssh-brute-force**
- Condition: 10+ Wazuh authentication failure alerts within 5 minutes
- Action: Create TheHive case with alert metadata
- Triggered at: 14:04:00 UTC

### Detection chain performance

The detection pipeline worked as designed. The first alert was generated within 45 seconds of the attack beginning, which is within acceptable bounds for an active brute-force scenario. The automated TheHive case creation reduced analyst manual effort and ensured no context was lost between the alert and the investigation.

---

## 6. Investigation Findings

### Confirmed: No Successful Authentication

A targeted Elasticsearch query was run against the `wazuh-alerts-*` index for any `Accepted password` or `Accepted publickey` event from source IP `192.168.56.30` during the attack window and for 30 minutes afterward. The query returned zero results, confirming that no authentication succeeded.

### Confirmed: No Post-Exploitation Activity

Wazuh process creation events and network connection logs on the target were reviewed for the 30 minutes following the attack. No unusual process executions, no new listening ports, no outbound connections to unexpected destinations, and no file integrity monitoring alerts were observed.

### Confirmed: No Lateral Movement

Log data from other hosts in the lab network showed no anomalous traffic originating from `soc-agent` during or after the attack window.

### Cortex Analysis Results

An AbuseIPDB lookup was run on `192.168.56.30` via Cortex. The IP is a private address (RFC 1918) and returned no results from public threat feeds — expected behaviour in a lab environment. In a production scenario, the attacker IP would be an internet-routable address, and an AbuseIPDB lookup would typically return useful reputation data.

### MISP Threat Intel Cross-Reference

The source IP was cross-referenced against the MISP instance's loaded feeds (Abuse.ch, AlienVault OTX). No matching entries were found — again expected for a private lab IP. In a real incident, this step would help determine whether the attacker is a known threat actor or part of a botnet.

---

## 7. Root Cause

The attack was made possible by two factors:

**Factor 1 — SSH exposed with no connection rate limiting**
The SSH service on `soc-agent` was accessible from any host on the lab network without IP-based restrictions, `fail2ban`, or `MaxAuthTries` configured in `sshd_config`. This allowed the attacker to send hundreds of requests without interruption.

**Factor 2 — No account lockout policy**
SSH on Linux does not implement account lockout by default. Without `fail2ban` or a similar mechanism, an attacker can attempt unlimited passwords without being blocked.

The attacker exploited these two gaps to execute an automated brute-force attack. The attack failed because targeted accounts had strong passwords (or did not exist), not because of any active defence on the target.

---

## 8. Remediation Actions Taken

The following actions were taken immediately after closing the investigation:

**1. Blocked attacker IP at the host firewall**

```bash
sudo ufw deny from 192.168.56.30 to any
sudo ufw reload
```

**2. Configured SSH MaxAuthTries**

Added to `/etc/ssh/sshd_config` on the target:

```
MaxAuthTries 3
LoginGraceTime 30
```

Then restarted the SSH daemon:

```bash
sudo systemctl restart sshd
```

**3. Installed and configured fail2ban**

```bash
sudo apt install fail2ban
```

Jail configuration in `/etc/fail2ban/jail.local`:

```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
```

**4. Verified SSH key-based authentication**

Confirmed that the monitored accounts use SSH key authentication. Password authentication was disabled for the root account (`PermitRootLogin prohibit-password` in `sshd_config`).

---

## 9. Recommendations

Beyond the immediate remediation, the following improvements are recommended for the lab environment (and apply directly to production environments):

**Short term**
- Deploy `fail2ban` on all SSH-exposed systems (done for this host)
- Set `MaxAuthTries 3` globally in the base SSH configuration template
- Disable password authentication for SSH entirely — enforce key-based auth only
- Restrict SSH access to a management VLAN or specific source IP ranges using firewall rules

**Medium term**
- Configure Wazuh active response to automatically block source IPs that trigger rule 5763 — this can be done with the built-in `firewall-drop` active response module
- Add a geolocation-based alert rule that fires when authentication attempts come from unexpected geographic regions
- Review all accounts on SSH-exposed systems and remove any unused accounts

**Long term**
- Implement a privileged access management (PAM) solution or jump host architecture to eliminate direct SSH exposure
- Enable multi-factor authentication for SSH using `pam_oath` or hardware tokens for privileged accounts
- Schedule quarterly reviews of SSH access logs and account audit

---

## 10. Lessons Learned

**Detection worked well.** The pipeline from raw log to TheHive case completed in under 2 minutes. The combination of Wazuh correlation rules and ElastAlert automated case creation meant that by the time I opened TheHive to investigate, all the context was already there.

**The custom rule added real value.** Writing rule 100001 with a tighter threshold caught the attack 20 seconds earlier than the default rule would have. In a real environment, those 20 seconds matter — especially if the attacker had correct credentials and only needed a few attempts.

**Detection gap: slow brute-force.** The current rule set would miss a slow brute-force attack that deliberately stays under the threshold — for example, one attempt every 3 minutes over a 24-hour period. Adding a daily frequency rule (e.g., 50+ failures from a single IP in 24 hours) would close that gap.

**Remediation should be part of the playbook.** During the exercise I added the fail2ban and firewall rules after the investigation, but these steps should be codified in the incident response playbook so they happen consistently across every similar incident.

---

## 11. References

| Resource | Link |
|---|---|
| MITRE ATT&CK — T1110.001 | https://attack.mitre.org/techniques/T1110/001/ |
| Wazuh rule 5763 documentation | https://documentation.wazuh.com |
| ElastAlert documentation | https://elastalert2.readthedocs.io |
| fail2ban documentation | https://www.fail2ban.org/wiki/index.php/Main_Page |
| TheHive documentation | https://docs.thehive-project.org |

---

*Report prepared by Ilyas Hodaiby — SOC Homelab Project*
*Classification: Lab — Non-production environment*
