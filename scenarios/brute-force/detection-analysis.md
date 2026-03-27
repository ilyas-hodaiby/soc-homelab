# Detection Analysis — SSH Brute-Force

**Analyst:** Ilyas Hodaiby
**Date:** 2024-11-12
**Attack type:** SSH brute-force (T1110.001)
**Verdict:** True Positive — No Compromise

---

## Purpose of This Document

This document explains in detail how the brute-force attack was detected — which rules fired, what the log data looked like at each stage, how I distinguished it from noise, and what the custom rule I wrote adds beyond Wazuh's defaults. This is the technical companion to the [scenario walkthrough](README.md).

---

## 1. Log Source Analysis

### Primary source: `/var/log/auth.log`

The Ubuntu target's SSH daemon writes authentication events to `/var/log/auth.log`. This is the ground-truth data source for this detection. The Wazuh agent monitors this file in real time using inotify and forwards new entries to the manager as they appear.

**Normal baseline (before attack):**
On a healthy system with no external exposure, `auth.log` might show 0–2 SSH failure events per hour — typically from automation scripts or misconfigured services. There would be no pattern of rapid sequential failures from a single source.

**During the attack:**
The failure rate jumped to approximately 60 events per minute from a single IP. This is immediately distinguishable from noise by three characteristics:

- **Volume:** 432 failures in ~3.5 minutes
- **Source consistency:** All failures share the same source IP (`192.168.56.30`)
- **Username variety:** The username field rotated through 8 distinct values — a pattern consistent with automated tooling

### Log entry anatomy

A single `auth.log` entry for an SSH failure:

```
Nov 12 14:02:16 soc-agent sshd[3415]: Failed password for invalid user admin from 192.168.56.30 port 54324 ssh2
```

Breaking this down:

| Field | Value | Significance |
|---|---|---|
| Timestamp | Nov 12 14:02:16 | Used for rate calculation |
| Hostname | soc-agent | Identifies the monitored endpoint |
| Process | sshd[3415] | New PID per attempt — normal for SSH |
| Event type | Failed password | Authentication failure |
| Username status | invalid user | Username does not exist on system |
| Username | admin | One of 8 attempted names |
| Source IP | 192.168.56.30 | Attacker's machine |
| Source port | 54324 | Ephemeral port — changes per connection |
| Protocol | ssh2 | SSH version 2 |

The `invalid user` keyword is particularly important. It means the username doesn't exist on the system at all SSH rejects it before even attempting password verification. This is a sign of username enumeration running in parallel with the brute-force.

---

## 2. Wazuh Rule Analysis

### Default rules that fired

**Rule 5760 — sshd: Authentication failed**

This is a low-severity rule (level 5) that fires on every individual SSH authentication failure. During the attack, this rule triggered 432 times — once per failed attempt. On its own, this rule produces too much noise to act on directly, but it feeds into the correlation rule below.

**Rule 5763 — sshd: Multiple authentication failures**

This is the high-severity rule (level 10) that triggered the alert. Wazuh's default configuration for this rule fires when the same source IP generates 8 or more rule 5760 events within a 120-second window.

The rule logic in Wazuh's XML format looks like this:

```xml
<rule id="5763" level="10" frequency="8" timeframe="120">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip/>
  <description>sshd: Multiple authentication failures.</description>
  <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,gpg13_7.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
</rule>
```

The `same_source_ip` condition is critical — it means all 8 events must come from the same IP to trigger the rule. This prevents it from firing on scattered, unrelated failures from different sources.

With 432 failures from a single IP in 3.5 minutes, this rule fired multiple times throughout the attack.

---

## 3. Custom Rule I Added

Beyond the default rules, I wrote a custom rule that fires earlier and with more context. The goal was to catch the attack faster and include the targeted username list in the alert.

**File:** `configs/wazuh/rules/custom-brute-force-rule.xml`

```xml
<group name="custom_ssh_bruteforce,">

  <!-- Fire at a lower threshold than default for faster detection -->
  <rule id="100001" level="12" frequency="5" timeframe="60">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip/>
    <description>Custom: SSH brute force detected - rapid auth failures from single source</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,brute_force</group>
  </rule>

  <!-- Detect invalid user attempts specifically (username enumeration) -->
  <rule id="100002" level="8" frequency="3" timeframe="30">
    <if_sid>5710</if_sid>
    <same_source_ip/>
    <description>Custom: Possible username enumeration via SSH - multiple invalid user attempts</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>authentication_failures,enumeration</group>
  </rule>

</group>
```

**Rule 100001** fires at 5 failures in 60 seconds, compared to the default 8 in 120. This gave me an alert roughly 20–30 seconds earlier in the attack timeline.

**Rule 100002** specifically targets username enumeration — the `invalid user` pattern. Wazuh's default ruleset detects it but doesn't correlate rapid sequences of it as a distinct enumeration behaviour. This rule gives that pattern its own alert and MITRE mapping (T1110.003 — Brute Force: Password Spraying) because the username rotation pattern is closer to spraying than pure brute-forcing.

---

## 4. Alert Data in Elasticsearch

When Wazuh sent the alert to ELK, Logstash parsed and enriched it. The resulting Elasticsearch document for the rule 5763 alert looked like this (simplified):

```json
{
  "@timestamp": "2024-11-12T14:02:45.000Z",
  "rule": {
    "id": "5763",
    "level": 10,
    "description": "sshd: Multiple authentication failures.",
    "groups": ["authentication_failures"]
  },
  "agent": {
    "id": "001",
    "name": "soc-agent",
    "ip": "192.168.56.20"
  },
  "data": {
    "srcip": "192.168.56.30",
    "srcport": "54324",
    "dstuser": "admin"
  },
  "full_log": "Nov 12 14:02:16 soc-agent sshd[3415]: Failed password for invalid user admin from 192.168.56.30 port 54324 ssh2",
  "location": "/var/log/auth.log",
  "geoip": {
    "country_name": "Private Range",
    "region_name": "Lab Network"
  }
}
```

This document structure is what Kibana queries and what ElastAlert evaluates when checking for threshold conditions.

---

## 5. Distinguishing True Positive from False Positive

When I first saw the alert in Kibana, I applied the following checks to determine whether this was a real attack or a false positive:

**Volume check:** 432 failures in 3.5 minutes is not realistic for a human user making mistakes. Even a developer repeatedly mistyping a password would generate at most 5–10 failures before stopping. This pattern screams automation.

**Source consistency check:** Every single failure came from `192.168.56.30`. A false positive from a misconfigured service would typically come from `localhost` or an internal service account, not a separate machine on the network.

**Username variety check:** Eight different usernames attempted from one source is a strong indicator of tooling. A legitimate user would only attempt their own username.

**Timing pattern check:** The inter-attempt interval was approximately 1 second — consistent with Hydra running at `-t 4` threads. Human behaviour is irregular; automated tooling is metronome-precise.

**Successful login check:** I searched Elasticsearch for any `Accepted password` or `Accepted publickey` event from `192.168.56.30` during and after the attack window. None found. The attack failed to authenticate.

**Lateral movement check:** I reviewed process creation events and outbound connection logs on the target VM for the 30 minutes following the attack. No unusual processes, no new network connections, no privilege escalation indicators.

**Conclusion:** All indicators pointed to a true positive brute-force attack that failed to achieve its objective. No compromise occurred.

---

## 6. Detection Gaps Identified

During this exercise I identified two detection gaps worth noting:

**Gap 1 — No alert on first failure from a new source IP**
The current setup only alerts after a threshold is met. A more advanced rule (or a threat-intel enrichment step) could flag the very first SSH attempt from an IP with no prior history in the environment — potentially catching slower, low-and-slow brute-force attempts that never hit the threshold.

**Gap 2 — No account lockout policy on the target**
The Ubuntu SSH configuration did not have `MaxAuthTries` or `fail2ban` configured. In a real environment, this would allow an attacker unlimited attempts. Adding `fail2ban` or `MaxAuthTries 3` in `sshd_config` would be the first remediation priority.

---

## 7. MITRE ATT&CK Mapping

| Technique | ID | Observed Behaviour |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Automated sequential password attempts against known username |
| Brute Force: Password Spraying | T1110.003 | Multiple usernames attempted from single source |
| Valid Accounts (attempted) | T1078 | Attacker aimed to obtain valid credentials for SSH access |

---

## 8. Key Takeaways

Working through this detection gave me a much clearer picture of what real alert triage looks like. The raw log volume during an active brute-force is significant — 432 individual events — and the analyst's job is to aggregate that signal, apply context, and reach a confident verdict quickly. The combination of Wazuh's correlation rules, Kibana's timeline visualisation, and structured investigation in TheHive made that process systematic rather than chaotic.

The custom rules I added were a direct result of working through this scenario — I noticed gaps in the default detection logic and wrote rules to address them. That kind of iterative rule refinement is a core part of what a SOC analyst does.
