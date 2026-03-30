# Incident Response Playbook — SSH Brute Force

**Playbook ID:** PB-001  
**Applies to:** Any SSH brute-force alert from Wazuh rule 5763 or custom rule 100001  
**Analyst:** Ilyas Hodaiby  

---

## Step 1 — Triage the Alert (5 minutes)

When a brute-force case arrives in TheHive:

- [ ] Note the source IP, target host, and timestamp
- [ ] Check how many failures were recorded and over what time window
- [ ] Check if the source IP has appeared in previous alerts

**Question to answer:** Is this volume and pattern consistent with automated tooling?
- Human mistake: 1–5 failures, single username, irregular timing
- Automated attack: 10+ failures, multiple usernames, machine-speed timing (~1/sec)

---

## Step 2 — Check for Successful Login (Critical — 3 minutes)

Search Elasticsearch for any successful authentication from the same source IP:

```
index: wazuh-alerts-*
query: data.srcip: "ATTACKER_IP" AND rule.id: "5715"
```

Rule 5715 = SSH authentication success.

- [ ] **If results found → ESCALATE IMMEDIATELY** — potential compromise
- [ ] **If no results → continue investigation**

---

## Step 3 — Enrich the Source IP (5 minutes)

- [ ] Run **Cortex AbuseIPDB analyser** on the source IP
- [ ] Run **Cortex VirusTotal analyser** on the source IP
- [ ] Cross-reference IP in **MISP** threat feeds
- [ ] Check if IP is internal (RFC 1918) or external (internet-routable)

**Record findings in the TheHive case observables.**

---

## Step 4 — Check for Post-Exploitation (10 minutes)

Even if no successful login was found, check for signs the attacker found another way in:

- [ ] Review process creation events on the target host in the same time window
- [ ] Check for new listening ports or outbound connections from the target
- [ ] Review file integrity monitoring (FIM) alerts from Wazuh on the target
- [ ] Check for privilege escalation events (sudo usage, `su` commands)

---

## Step 5 — Containment (if active attack)

If the attack is still ongoing:

```bash
# Block attacker IP immediately
sudo ufw deny from ATTACKER_IP to any
sudo ufw reload

# Verify block is in place
sudo ufw status | grep ATTACKER_IP
```

For Wazuh active response (automated), the `firewall-drop` module can be configured to do this automatically when rule 5763 fires.

---

## Step 6 — Document and Close

- [ ] Update TheHive case with all findings
- [ ] Add source IP as an observable (type: IP)
- [ ] Tag the case: `brute-force`, `ssh`, `T1110.001`
- [ ] Set verdict: True Positive or False Positive
- [ ] Add closing note: what happened, what was confirmed, what action was taken

**Close case with one of:**
- `True Positive — No Compromise` — attack detected, no successful login
- `True Positive — Compromised` — successful login found, escalate
- `False Positive` — legitimate tool or misconfigured service, document why

---

## Step 7 — Post-Incident Recommendations

After closing, check whether these hardening steps are in place on the target:

- [ ] `fail2ban` installed and configured
- [ ] `MaxAuthTries 3` in `/etc/ssh/sshd_config`
- [ ] Password auth disabled for root (`PermitRootLogin prohibit-password`)
- [ ] SSH access restricted to known IPs or management VLAN if possible
- [ ] Alert the asset owner if this was an externally accessible host
