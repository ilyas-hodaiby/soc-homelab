# Tools Setup Notes

## Wazuh Manager
- Version: 4.7
- OS: Ubuntu 22.04
- Port: 1514 (agent), 1515 (enrollment)
- Config file: /var/ossec/etc/ossec.conf

## Elasticsearch
- Version: 8.11
- Port: 9200
- Index pattern: wazuh-alerts-*

## Kibana
- Version: 8.11
- Port: 5601
- Dashboard: SOC Overview

## TheHive
- Version: 5.x
- Port: 9000
- Connected to: Cortex, MISP

## ElastAlert
- Version: 2.x
- Check interval: 2 minutes
- Alert type: TheHive case creation
