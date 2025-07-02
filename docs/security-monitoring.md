# Security Monitoring Guide 🔍

This guide covers the implementation of comprehensive security monitoring for your smart home infrastructure, including network monitoring, intrusion detection, and automated threat response.

## Overview

Security monitoring in a smart home environment requires multiple layers of detection and response capabilities to protect against various threats targeting IoT devices and network infrastructure.

## Network Monitoring Stack

### Suricata IDS/IPS

Suricata provides real-time intrusion detection and prevention capabilities.

#### Installation

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install suricata

# Configure Suricata
sudo suricata-update
sudo systemctl enable suricata
sudo systemctl start suricata
```

#### Configuration

```yaml
# /etc/suricata/suricata.yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    IOT_NET: "[192.168.30.0/24]"
    SECURITY_NET: "[192.168.40.0/24]"
    TRUSTED_NET: "[192.168.20.0/24]"
    MANAGEMENT_NET: "[192.168.10.0/24]"

  port-groups:
    HTTP_PORTS: "80"
    HTTPS_PORTS: "443"
    SSH_PORTS: "22"

# Rule files
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - iot-security.rules
  - custom-rules.rules

# Outputs
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - anomaly
        - http
        - dns
        - tls
        - files
        - smtp
        - ssh
        - stats
        - flow

  - unified2-alert:
      enabled: yes
      filename: unified2.alert

# Logging
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log
```

### Custom IoT Security Rules

```bash
# /var/lib/suricata/rules/iot-security.rules

# IoT Device Communication Monitoring
alert tcp $IOT_NET any -> $EXTERNAL_NET any (msg:"IoT device unexpected outbound connection"; flow:to_server,established; sid:1000001; rev:1;)
alert tcp $IOT_NET any -> $IOT_NET any (msg:"IoT device lateral movement attempt"; flow:to_server,established; sid:1000002; rev:1;)
alert tcp any any -> $IOT_NET any (msg:"Inbound connection to IoT device"; flow:to_server,established; sid:1000003; rev:1;)

# DNS Monitoring
alert dns $IOT_NET any -> any 53 (msg:"IoT device suspicious DNS query"; dns_query; content:"malware"; nocase; sid:1000004; rev:1;)
alert dns $IOT_NET any -> any 53 (msg:"IoT device DGA domain query"; dns_query; pcre:"/^[a-z]{8,}\.com$/"; sid:1000005; rev:1;)

# Protocol Anomalies
alert tcp $IOT_NET any -> any any (msg:"IoT device unusual port usage"; dsize:>1000; sid:1000006; rev:1;)
alert udp $IOT_NET any -> $EXTERNAL_NET 53 (msg:"IoT device excessive DNS queries"; threshold:type both,track by_src,count 50,seconds 60; sid:1000007; rev:1;)

# Security Camera Specific Rules
alert tcp $SECURITY_NET any -> $EXTERNAL_NET any (msg:"Security camera unexpected outbound connection"; flow:to_server,established; sid:1000008; rev:1;)
alert tcp any any -> $SECURITY_NET 554 (msg:"RTSP access to security camera"; flow:to_server,established; content:"RTSP"; sid:1000009; rev:1;)

# Smart Speaker Monitoring
alert tcp $IOT_NET any -> $EXTERNAL_NET 443 (msg:"Smart speaker cloud communication"; flow:to_server,established; content:"alexa"; nocase; sid:1000010; rev:1;)
alert tcp $IOT_NET any -> $EXTERNAL_NET 443 (msg:"Smart speaker cloud communication"; flow:to_server,established; content:"google"; nocase; sid:1000011; rev:1;)
```

### ntopng Network Monitoring

```bash
# /etc/ntopng/ntopng.conf

# Network interfaces
-i=eth0.10  # Management VLAN
-i=eth0.20  # Trusted devices VLAN
-i=eth0.30  # IoT VLAN
-i=eth0.40  # Security devices VLAN

# Web interface
-P=/var/lib/ntopng/ntopng.pid
-d=/var/lib/ntopng
-w=3000

# Authentication
-u=ntopng
-g=ntopng

# Logging
--syslog=daemon

# Data retention
--dump-flows=mysql
--mysql="host=localhost;dbname=ntopng;user=ntopng;password=PASSWORD"

# Alerts
--alerts-manager
--alert-endpoint=http://localhost:8123/api/webhook/ntopng_alert

# Geolocation
--geoip-asn-list=/var/lib/GeoIP/GeoLite2-ASN.mmdb
--geoip-city-list=/var/lib/GeoIP/GeoLite2-City.mmdb
```

## SIEM Integration

### ELK Stack Setup

#### Elasticsearch Configuration

```yaml
# /etc/elasticsearch/elasticsearch.yml
cluster.name: smart-home-siem
node.name: siem-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 192.168.10.100
http.port: 9200
discovery.type: single-node

# Security
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true
```

#### Logstash Configuration

```ruby
# /etc/logstash/conf.d/suricata.conf
input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => json
    type => "suricata"
  }
}

filter {
  if [type] == "suricata" {
    if [event_type] == "alert" {
      mutate {
        add_tag => ["security_alert"]
      }
      
      # Enrich with threat intelligence
      if [alert][signature_id] {
        elasticsearch {
          hosts => ["localhost:9200"]
          index => "threat-intel"
          query => "signature_id:%{[alert][signature_id]}"
          fields => { "threat_level" => "threat_level" }
        }
      }
    }
    
    # GeoIP enrichment
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "src_geoip"
      }
    }
    
    if [dest_ip] {
      geoip {
        source => "dest_ip"
        target => "dest_geoip"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
  }
  
  # Send high-priority alerts to Home Assistant
  if "security_alert" in [tags] and [alert][severity] <= 2 {
    http {
      url => "http://192.168.10.50:8123/api/webhook/security_alert"
      http_method => "post"
      format => "json"
      mapping => {
        "alert_id" => "%{[alert][signature_id]}"
        "message" => "%{[alert][signature]}"
        "severity" => "%{[alert][severity]}"
        "src_ip" => "%{[src_ip]}"
        "dest_ip" => "%{[dest_ip]}"
        "timestamp" => "%{[@timestamp]}"
      }
    }
  }
}
```

### Kibana Dashboards

#### Security Overview Dashboard

```json
{
  "version": "7.15.0",
  "objects": [
    {
      "id": "security-overview",
      "type": "dashboard",
      "attributes": {
        "title": "Smart Home Security Overview",
        "hits": 0,
        "description": "Overview of security events and network activity",
        "panelsJSON": "[{\"version\":\"7.15.0\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15,\"i\":\"1\"},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"}]",
        "timeRestore": false,
        "kibanaSavedObjectMeta": {
          "searchSourceJSON": "{\"query\":{\"match_all\":{}},\"filter\":[]}"
        }
      }
    }
  ]
}
```

## Automated Threat Response

### Home Assistant Security Automations

```yaml
# automations.yaml
- alias: "High Severity Security Alert"
  trigger:
    - platform: webhook
      webhook_id: security_alert
  condition:
    - condition: template
      value_template: "{{ trigger.json.severity|int <= 2 }}"
  action:
    - service: notify.security_team
      data:
        title: "🚨 High Severity Security Alert"
        message: |
          Alert: {{ trigger.json.message }}
          Source IP: {{ trigger.json.src_ip }}
          Destination IP: {{ trigger.json.dest_ip }}
          Severity: {{ trigger.json.severity }}
    - service: script.isolate_suspicious_device
      data:
        device_ip: "{{ trigger.json.src_ip }}"

- alias: "IoT Device Anomaly Detection"
  trigger:
    - platform: state
      entity_id: binary_sensor.network_anomaly
      to: 'on'
  action:
    - service: script.enhanced_monitoring_mode
    - service: notify.admin
      data:
        title: "Network Anomaly Detected"
        message: "Unusual network activity detected on IoT VLAN"
    - delay: '00:05:00'
    - service: script.analyze_network_traffic

- alias: "Failed Authentication Attempts"
  trigger:
    - platform: numeric_state
      entity_id: sensor.failed_auth_attempts
      above: 5
      for: '00:01:00'
  action:
    - service: script.lockdown_mode
    - service: notify.security_team
      data:
        title: "🔒 Multiple Failed Authentication Attempts"
        message: "{{ states('sensor.failed_auth_attempts') }} failed attempts in the last minute"
```

### Security Scripts

```yaml
# scripts.yaml
isolate_suspicious_device:
  alias: "Isolate Suspicious Device"
  sequence:
    - service: shell_command.quarantine_device
      data:
        device_ip: "{{ device_ip }}"
    - service: notify.admin
      data:
        title: "Device Isolated"
        message: "Device {{ device_ip }} has been moved to quarantine VLAN"

enhanced_monitoring_mode:
  alias: "Enable Enhanced Monitoring"
  sequence:
    - service: shell_command.enable_packet_capture
    - service: input_boolean.turn_on
      entity_id: input_boolean.enhanced_monitoring
    - delay: '01:00:00'
    - service: input_boolean.turn_off
      entity_id: input_boolean.enhanced_monitoring
    - service: shell_command.disable_packet_capture

lockdown_mode:
  alias: "Emergency Lockdown"
  sequence:
    - service: shell_command.emergency_firewall_rules
    - service: input_boolean.turn_on
      entity_id: input_boolean.lockdown_mode
    - service: light.turn_on
      entity_id: light.security_status
      data:
        color_name: red
        brightness: 255
    - service: notify.all_devices
      data:
        title: "🚨 SECURITY LOCKDOWN ACTIVATED"
        message: "Emergency security measures have been activated"
```

## Monitoring Metrics and KPIs

### Key Security Metrics

1. **Network Traffic Metrics:**
   - Bandwidth utilization per VLAN
   - Connection attempts to IoT devices
   - Outbound connections from IoT VLAN
   - DNS query patterns

2. **Security Event Metrics:**
   - IDS/IPS alert frequency
   - Failed authentication attempts
   - Firewall block events
   - Malware detection events

3. **Device Health Metrics:**
   - Device availability
   - Firmware version compliance
   - Certificate expiration dates
   - Last communication timestamps

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "security_rules.yml"
  - "iot_rules.yml"

scrape_configs:
  - job_name: 'suricata'
    static_configs:
      - targets: ['localhost:9200']
    metrics_path: '/suricata/_search'
    params:
      q: ['event_type:stats']

  - job_name: 'ntopng'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/lua/rest/v1/get/interface/data.lua'

  - job_name: 'home-assistant'
    static_configs:
      - targets: ['192.168.10.50:8123']
    metrics_path: '/api/prometheus'
    bearer_token: 'YOUR_LONG_LIVED_ACCESS_TOKEN'

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Security Dashboard

```json
{
  "dashboard": {
    "title": "Smart Home Security Dashboard",
    "tags": ["security", "iot"],
    "panels": [
      {
        "title": "Security Alerts Over Time",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(suricata_alerts_total[5m])",
            "legendFormat": "Alerts per second"
          }
        ]
      },
      {
        "title": "IoT Device Status",
        "type": "stat",
        "targets": [
          {
            "expr": "count(up{job=\"iot_devices\"})",
            "legendFormat": "Total Devices"
          },
          {
            "expr": "count(up{job=\"iot_devices\"} == 1)",
            "legendFormat": "Online Devices"
          }
        ]
      },
      {
        "title": "Network Traffic by VLAN",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(interface_bytes_total[5m])",
            "legendFormat": "{{ vlan }}"
          }
        ]
      }
    ]
  }
}
```

## Incident Response Procedures

### Automated Response Workflows

1. **High Severity Alert Response:**
   ```bash
   #!/bin/bash
   # high-severity-response.sh
   
   ALERT_ID=$1
   SOURCE_IP=$2
   SEVERITY=$3
   
   # Log incident
   echo "$(date): High severity alert $ALERT_ID from $SOURCE_IP" >> /var/log/security-incidents.log
   
   # Isolate device if from IoT VLAN
   if [[ $SOURCE_IP =~ ^192\.168\.30\. ]]; then
       ./isolate-device.sh $SOURCE_IP
   fi
   
   # Capture network traffic
   tcpdump -i any -w /tmp/incident-$ALERT_ID-$(date +%Y%m%d-%H%M%S).pcap host $SOURCE_IP &
   TCPDUMP_PID=$!
   sleep 300  # Capture for 5 minutes
   kill $TCPDUMP_PID
   
   # Generate incident report
   ./generate-incident-report.sh $ALERT_ID $SOURCE_IP $SEVERITY
   ```

2. **Device Compromise Response:**
   ```bash
   #!/bin/bash
   # device-compromise-response.sh
   
   DEVICE_IP=$1
   DEVICE_MAC=$2
   
   # Immediate isolation
   ./isolate-device.sh $DEVICE_IP $DEVICE_MAC
   
   # Forensic data collection
   ./collect-forensic-data.sh $DEVICE_IP
   
   # Notify security team
   curl -X POST http://192.168.10.50:8123/api/webhook/device_compromise \
        -H "Content-Type: application/json" \
        -d "{\"device_ip\":\"$DEVICE_IP\",\"device_mac\":\"$DEVICE_MAC\",\"timestamp\":\"$(date -Iseconds)\"}"
   ```

## Threat Intelligence Integration

### MISP Integration

```python
# threat_intel_updater.py
import requests
import json
from pymisp import PyMISP

class ThreatIntelUpdater:
    def __init__(self, misp_url, misp_key):
        self.misp = PyMISP(misp_url, misp_key, ssl=False)
    
    def update_iot_indicators(self):
        # Search for IoT-related events
        events = self.misp.search(tags=['iot', 'botnet'], published=True)
        
        indicators = []
        for event in events:
            for attribute in event.get('Attribute', []):
                if attribute['type'] in ['ip-dst', 'domain', 'url']:
                    indicators.append({
                        'value': attribute['value'],
                        'type': attribute['type'],
                        'category': attribute['category'],
                        'comment': attribute.get('comment', '')
                    })
        
        # Update Suricata rules
        self.update_suricata_rules(indicators)
        
        # Update firewall blocklist
        self.update_firewall_blocklist(indicators)
    
    def update_suricata_rules(self, indicators):
        rules = []
        for indicator in indicators:
            if indicator['type'] == 'ip-dst':
                rule = f'alert tcp $IOT_NET any -> {indicator["value"]} any (msg:"IoT device connecting to known malicious IP"; sid:{self.get_next_sid()}; rev:1;)'
                rules.append(rule)
        
        with open('/var/lib/suricata/rules/threat-intel.rules', 'w') as f:
            f.write('\n'.join(rules))
    
    def update_firewall_blocklist(self, indicators):
        ips = [i['value'] for i in indicators if i['type'] == 'ip-dst']
        
        # Update pfSense blocklist
        with open('/tmp/threat-intel-ips.txt', 'w') as f:
            f.write('\n'.join(ips))
        
        # Reload firewall rules
        subprocess.run(['pfctl', '-t', 'threat_intel', '-T', 'replace', '-f', '/tmp/threat-intel-ips.txt'])
```

## Performance Optimization

### Resource Management

1. **Log Rotation:**
   ```bash
   # /etc/logrotate.d/security-monitoring
   /var/log/suricata/*.log {
       daily
       rotate 30
       compress
       delaycompress
       missingok
       notifempty
       postrotate
           systemctl reload suricata
       endscript
   }
   
   /var/log/ntopng/*.log {
       daily
       rotate 7
       compress
       delaycompress
       missingok
       notifempty
   }
   ```

2. **Database Optimization:**
   ```sql
   -- Elasticsearch index lifecycle management
   PUT _ilm/policy/security-logs-policy
   {
     "policy": {
       "phases": {
         "hot": {
           "actions": {
             "rollover": {
               "max_size": "5GB",
               "max_age": "7d"
             }
           }
         },
         "warm": {
           "min_age": "7d",
           "actions": {
             "allocate": {
               "number_of_replicas": 0
             }
           }
         },
         "delete": {
           "min_age": "30d"
         }
       }
     }
   }
   ```

## Compliance and Reporting

### Automated Reporting

```python
# security_report_generator.py
import pandas as pd
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

class SecurityReportGenerator:
    def __init__(self, elasticsearch_host):
        self.es_host = elasticsearch_host
    
    def generate_weekly_report(self):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        # Collect metrics
        alerts = self.get_security_alerts(start_date, end_date)
        traffic = self.get_network_traffic(start_date, end_date)
        devices = self.get_device_status()
        
        # Generate report
        report = {
            'period': f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
            'total_alerts': len(alerts),
            'high_severity_alerts': len([a for a in alerts if a['severity'] <= 2]),
            'unique_source_ips': len(set([a['src_ip'] for a in alerts])),
            'top_alert_types': self.get_top_alert_types(alerts),
            'network_traffic_gb': sum(traffic.values()) / (1024**3),
            'device_availability': self.calculate_device_availability(devices)
        }
        
        # Generate visualizations
        self.create_alert_trend_chart(alerts)
        self.create_traffic_distribution_chart(traffic)
        
        return report
    
    def get_security_alerts(self, start_date, end_date):
        # Query Elasticsearch for security alerts
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event_type": "alert"}},
                        {"range": {"@timestamp": {
                            "gte": start_date.isoformat(),
                            "lte": end_date.isoformat()
                        }}}
                    ]
                }
            }
        }
        # Implementation details...
        return []
```

## Best Practices

1. **Regular Security Assessments:**
   - Weekly vulnerability scans
   - Monthly penetration testing
   - Quarterly security reviews

2. **Continuous Monitoring:**
   - 24/7 automated monitoring
   - Real-time alerting
   - Proactive threat hunting

3. **Incident Response:**
   - Documented procedures
   - Regular drills
   - Post-incident reviews

4. **Compliance:**
   - Regular audits
   - Documentation maintenance
   - Training and awareness

## Additional Resources

- [Suricata User Guide](https://suricata.readthedocs.io/)
- [ELK Stack Security Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [IoT Security Best Practices](https://www.iotsecurityfoundation.org/)