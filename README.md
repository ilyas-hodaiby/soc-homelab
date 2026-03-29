# 🛡️ SOC Homelab — Threat Detection & Incident Response Lab

> **Built by Ilyas Hodaiby** — A fully operational Security Operations Center lab simulating real-world threat detection, log analysis, alerting, and incident response using industry-standard tools.

---

## 📌 Overview

This project is a hands-on SOC lab I built from scratch to simulate how a real Security Operations Center detects, investigates, and responds to cyber threats. I deployed a full detection and response stack across multiple virtual machines, configured each tool end-to-end, and ran a live SSH brute-force attack simulation to validate the entire pipeline — from raw log ingestion to a closed incident case.

The goal was to understand SOC workflows at a practical level: how logs travel through a pipeline, how alerts get triggered and tuned, and how analysts manage incidents from detection to resolution.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOC HOMELAB NETWORK                       │
│                                                                  │
│  ┌──────────────┐    Wazuh Agent     ┌──────────────────────┐   │
│  │  Kali Linux  │ ─────────────────► │   Wazuh Manager      │   │
│  │  (Attacker)  │                    │   (SIEM + EDR)        │   │
│  └──────────────┘                    └──────────┬───────────┘   │
│                                                 │               │
│  ┌──────────────┐                               │ Logstash      │
│  │ Ubuntu Agent │ ─── Wazuh Agent ──────────────┤               │
│  │  (Target)    │                               ▼               │
│  └──────────────┘               ┌───────────────────────────┐   │
│                                 │      ELK Stack             │   │
│                                 │  Elasticsearch (storage)   │   │
│                                 │  Logstash (pipeline)       │   │
│                                 │  Kibana (dashboards)       │   │
│                                 └──────────────┬────────────┘   │
│                                                │                │
│                         ┌──────────────────────┤                │
│                         │                      │                │
│                         ▼                      ▼                │
│               ┌──────────────────┐   ┌──────────────────┐      │
│               │   ElastAlert     │   │  MISP (Threat    │      │
│               │   (Alerting)     │   │  Intelligence)   │      │
│               └────────┬─────────┘   └────────┬─────────┘      │
│                        │                      │                 │
│                        └──────────┬───────────┘                 │
│                                   ▼                             │
│                        ┌─────────────────────┐                 │
│                        │  TheHive + Cortex    │                 │
│                        │  (IR + SOAR)         │                 │
│                        └─────────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

📄 See [docs/architecture.md](docs/architecture.md) for a full breakdown of the data flow and component roles.

---

## 🧰 Tools & Stack

| Tool | Role | Version |
|---|---|---|
| **Wazuh** | SIEM + EDR — agent-based log collection, threat detection, custom rules | 4.7 |
| **Elasticsearch** | Log storage and full-text search backend | 8.11 |
| **Logstash** | Log ingestion and enrichment pipeline | 8.11 |
| **Kibana** | Visualisation, dashboards, and alert monitoring | 8.11 |
| **ElastAlert** | Rule-based alerting engine on top of Elasticsearch | 2.x |
| **MISP** | Threat intelligence platform — IOC sharing and enrichment | 2.4 |
| **TheHive** | Incident case management and investigation platform | 5.x |
| **Cortex** | Automated IOC analysis and response engine | 3.x |

---

## 🎯 Attack Scenario: SSH Brute Force

### What I simulated

I used **Hydra** on a Kali Linux machine to launch an SSH brute-force attack against an Ubuntu target running a Wazuh agent. The attack generated hundreds of failed authentication attempts within a short window, triggering alerts across the detection stack.

### Full pipeline — what happened

```
Hydra (Kali) ──► SSH failed logins (Ubuntu) ──► Wazuh Agent collects auth.log
    ──► Wazuh Manager detects pattern (Rule 5763) ──► Alert forwarded to Logstash
    ──► Indexed in Elasticsearch ──► Visualised in Kibana dashboard
    ──► ElastAlert fires notification ──► Incident created in TheHive
    ──► IOCs cross-referenced in MISP ──► Case investigated and closed
```

### Key results

| Metric | Value |
|---|---|
| Attack duration | ~3 minutes |
| Failed login attempts | 432 |
| Unique usernames tried | 8 |
| Alert trigger threshold | 8 failed attempts in 120 seconds |
| Wazuh rule triggered | Rule ID 5763 — Multiple authentication failures |
| MITRE ATT&CK technique | T1110.001 — Brute Force: Password Guessing |
| Time to alert | < 60 seconds from attack start |
| Incident status | Closed — True Positive |

📄 Full walkthrough: [scenarios/brute-force/README.md](scenarios/brute-force/README.md)
📄 Detection analysis: [scenarios/brute-force/detection-analysis.md](scenarios/brute-force/detection-analysis.md)
📄 Incident report: [reports/incident-report-brute-force.md](reports/incident-report-brute-force.md)

---

## 🔍 Key Skills Demonstrated

**SIEM & Log Management**
- Deployed and configured Wazuh agents across multiple Linux endpoints
- Built a Logstash ingestion pipeline for structured log forwarding
- Wrote a custom Wazuh rule to detect brute-force patterns beyond default thresholds
- Tuned alert thresholds to reduce false positives

**Threat Detection**
- Analysed `auth.log` and Wazuh alerts to identify attack patterns
- Mapped observed behaviour to MITRE ATT&CK (T1110.001)
- Extracted and documented IOCs: source IP, targeted usernames, timestamps

**Alerting & Automation**
- Configured ElastAlert with a frequency-based rule for SSH failure spikes
- Set up alert routing to TheHive case creation

**Threat Intelligence**
- Integrated MISP feeds into TheHive for IOC enrichment
- Cross-referenced attacker IP against threat intelligence during investigation

**Incident Response**
- Managed the full incident lifecycle in TheHive: creation → investigation → closure
- Used Cortex to automate IP reputation analysis
- Produced a structured incident report with timeline, IOCs, root cause, and remediation

---

## 🖥️ Lab Environment

| Component | OS | RAM | CPU |
|---|---|---|---|
| Wazuh Manager + ELK | Ubuntu 22.04 LTS | 8 GB | 4 vCPU |
| TheHive + Cortex + MISP | Ubuntu 22.04 LTS | 6 GB | 2 vCPU |
| Wazuh Agent (target) | Ubuntu 22.04 LTS | 2 GB | 1 vCPU |
| Kali Linux (attacker) | Kali Rolling | 2 GB | 1 vCPU |
| Hypervisor | VirtualBox / VMware | — | — |

---

## 📂 Repository Structure

```
soc-homelab/
│
├── README.md
├── docs/
│   ├── architecture.md
│   └── setup/
│       ├── wazuh-setup.md
│       ├── elk-setup.md
│       ├── misp-setup.md
│       └── thehive-setup.md
├── configs/
│   ├── wazuh/
│   │   ├── ossec.conf
│   │   └── rules/custom-brute-force-rule.xml
│   ├── elk/
│   │   └── logstash-pipeline.conf
│   ├── elastalert/
│   │   └── ssh-brute-force-rule.yaml
│   └── thehive/
│       └── application.conf
├── scenarios/
│   ├── brute-force/
│   │   ├── README.md
│   │   └── detection-analysis.md
│   └── playbooks/
│       └── brute-force-playbook.md
├── screenshots/
│   └── (add your screenshots here)
├── logs/
│   └── sample-brute-force.log
└── reports/
    └── incident-report-brute-force.md
```

---

## 👤 About

**Ilyas Hodaiby** — MSc Computer Science student at Ulster University London  
Aspiring SOC Analyst | Cybersecurity Student | Preparing for eCTHP

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/ilyas-hodaiby)
