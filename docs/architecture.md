# Lab Architecture

This document describes how the SOC homelab is structured, how data flows between components, and the role each tool plays in the detection and response pipeline.

---

## Overview

The lab is built across four virtual machines on a host-only network. Each VM has a specific role that mirrors a real SOC environment: a monitored endpoint, a centralised SIEM, a detection and response platform, and an attacker machine used to simulate threats. No traffic leaves the lab — everything is isolated.

---

## Network Layout

| VM | Hostname | IP Address | Role |
|---|---|---|---|
| Wazuh Manager + ELK | soc-manager | 192.168.56.10 | SIEM, log storage, dashboards |
| TheHive + Cortex + MISP | soc-ir | 192.168.56.11 | Incident response, threat intel |
| Ubuntu Agent | soc-agent | 192.168.56.20 | Monitored endpoint (attack target) |
| Kali Linux | soc-kali | 192.168.56.30 | Attacker machine |

---

## Data Flow — Step by Step

### Step 1 — Log Collection
The Wazuh agent runs on the Ubuntu target and monitors `/var/log/auth.log`, `/var/log/syslog`, and file integrity. All events are forwarded to the Wazuh Manager over port 1514.

### Step 2 — Detection
The Wazuh Manager checks events against its ruleset in real time. When a rule matches — for example, 8+ failed SSH logins in 120 seconds — it generates an alert with a severity level and rule ID, then forwards it to ELK.

### Step 3 — Ingestion into ELK
Logstash receives the Wazuh alert, parses the JSON, enriches it with GeoIP data, and sends it to Elasticsearch. Alerts are stored under the index pattern `wazuh-alerts-*`.

### Step 4 — Visualisation in Kibana
The Kibana dashboard shows total alerts by severity, top triggered rules, alerts over time, and source IP distribution. During the brute-force simulation, it showed a clear spike in authentication failure events from a single source IP.

### Step 5 — ElastAlert Notifications
ElastAlert monitors Elasticsearch every 2 minutes. When it finds 10+ SSH failure events in a 5-minute window, it fires and creates a case in TheHive via API.

### Step 6 — Threat Intelligence (MISP)
MISP is loaded with open-source feeds (Abuse.ch, AlienVault OTX). During investigation, TheHive connects to MISP to cross-reference IOCs like source IPs against known threat intelligence.

### Step 7 — Incident Response (TheHive + Cortex)
ElastAlert creates the case in TheHive with alert details pre-filled. The analyst then reviews evidence, runs Cortex analysers on IOCs (e.g. AbuseIPDB lookup), documents findings, and closes the case.

---

## Component Summary

| Tool | What it does in this lab |
|---|---|
| **Wazuh** | Collects SSH logs from Ubuntu agent, fires rule 5763 on brute-force pattern, forwards alert to ELK |
| **Logstash** | Receives Wazuh alerts, parses and enriches them, sends to Elasticsearch |
| **Elasticsearch** | Stores all alerts in a searchable, time-based index |
| **Kibana** | Displays real-time dashboard showing the spike in authentication failures |
| **ElastAlert** | Detects the alert spike and auto-creates a case in TheHive |
| **MISP** | Provides threat intelligence lookups during investigation |
| **TheHive** | Case management workspace — investigation, tasks, IOC tracking, closure |
| **Cortex** | Runs automated IP reputation analysis on the attacker's IP |

---

## Design Decisions

**Why separate VMs for IR tools?**
Keeping TheHive, Cortex, and MISP on a dedicated VM mirrors production deployments — separate from the SIEM for resource isolation and access control.

**Why Wazuh instead of pure ELK?**
Wazuh adds agent management, file integrity monitoring, and a pre-built rule set on top of ELK. This better represents a real SOC stack where the SIEM includes EDR capability.

**Why ElastAlert over Kibana alerting?**
ElastAlert offers more control over rule logic and natively integrates with TheHive's API — a more realistic and transferable skill for SOC work.
