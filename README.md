# Secure Smart Home Infrastructure 🏠🔒

This repository documents the implementation of a secure smart home infrastructure using Home Assistant with a strong focus on IoT security through VLAN segregation, network monitoring, and device isolation. The setup ensures that IoT devices are properly contained while maintaining functionality and ease of use.

**Important Note:** IoT security is complex and evolving. The configurations provided here represent current best practices but should be regularly reviewed and updated as new threats emerge.

## 🎯 Goals

* Create a centrally managed smart home environment
* Isolate IoT devices from critical network infrastructure
* Implement comprehensive network monitoring and alerting
* Ensure secure remote access to smart home systems
* Maintain device functionality while maximizing security
* Provide automated threat detection and response

## 🛠️ Technologies Used

* [Home Assistant](https://www.home-assistant.io/) - Smart home automation platform
* [VLAN](https://en.wikipedia.org/wiki/Virtual_LAN) - Network segmentation
* [pfSense](https://www.pfsense.org/) or [OPNsense](https://opnsense.org/) - Firewall/Router
* [Unifi Network](https://ui.com/consoles) - Network infrastructure (optional)
* [Zigbee2MQTT](https://www.zigbee2mqtt.io/) - Zigbee device management
* [Node-RED](https://nodered.org/) - Flow-based automation
* [InfluxDB](https://www.influxdata.com/) - Time series database
* [Grafana](https://grafana.com/) - Monitoring and visualization
* [Suricata](https://suricata.io/) - Network IDS/IPS
* [Docker](https://www.docker.com/) - Containerization

## ✨ Key Features/Highlights

* **Network Segmentation:** VLANs isolate IoT devices from critical systems
* **Zero Trust Architecture:** No device is trusted by default
* **Comprehensive Monitoring:** Real-time network traffic analysis
* **Automated Security:** IDS/IPS with automated threat response
* **Secure Remote Access:** VPN-only external access
* **Device Discovery:** Automated IoT device identification and classification
* **Firmware Management:** Centralized IoT device update management
* **Privacy Protection:** Local processing, minimal cloud dependencies
* **Incident Response:** Automated isolation of compromised devices

## 🏛️ Repository Structure

```
secure-smart-home-infrastructure/
├── README.md
├── docs/
│   ├── network-architecture.md
│   ├── vlan-configuration.md
│   ├── home-assistant-setup.md
│   ├── security-monitoring.md
│   ├── device-onboarding.md
│   └── incident-response.md
├── network/
│   ├── firewall-rules/
│   │   ├── pfsense-config.xml.example
│   │   └── opnsense-config.xml.example
│   ├── vlan-configs/
│   │   ├── switch-config.txt
│   │   └── unifi-config.json
│   └── monitoring/
│       ├── suricata.yaml
│       └── ntopng.conf
├── config-examples/
│   ├── home-assistant/
│   │   ├── configuration.yaml
│   │   ├── automations.yaml
│   │   └── secrets.yaml.example
│   ├── zigbee2mqtt/
│   │   └── configuration.yaml
│   ├── node-red/
│   │   └── flows.json.example
│   └── docker/
│       └── docker-compose.yml
└── scripts/
    ├── setup/
    │   ├── initial-network-setup.sh
    │   ├── vlan-setup.sh
    │   └── device-discovery.sh
    ├── monitoring/
    │   ├── network-monitor.sh
    │   ├── device-health-check.sh
    │   └── security-scan.sh
    └── incident-response/
        ├── isolate-device.sh
        ├── emergency-lockdown.sh
        └── forensic-capture.sh
```

## 🌐 Network Architecture

### VLAN Segmentation

```
VLAN 10 - Management (192.168.10.0/24)
├── Network equipment management
├── Home Assistant server
└── Monitoring systems

VLAN 20 - Trusted Devices (192.168.20.0/24)
├── Personal computers
├── Smartphones/tablets
└── Trusted servers

VLAN 30 - IoT Devices (192.168.30.0/24)
├── Smart lights, switches
├── Sensors and thermostats
└── Smart speakers (isolated)

VLAN 40 - Security Devices (192.168.40.0/24)
├── Security cameras
├── Door locks
└── Motion sensors

VLAN 50 - Guest Network (192.168.50.0/24)
├── Guest devices
└── Temporary access

VLAN 60 - Quarantine (192.168.60.0/24)
├── New/unknown devices
├── Potentially compromised devices
└── Firmware update staging
```

### Firewall Rules

#### Inter-VLAN Communication Rules

1. **Management VLAN (10) → All VLANs**
   - Full access for administration
   - Logging enabled for all connections

2. **Trusted Devices (20) → IoT Devices (30)**
   - Allow Home Assistant communication
   - Block direct device-to-device communication
   - Rate limiting applied

3. **IoT Devices (30) → Internet**
   - Allow necessary cloud services only
   - Block peer-to-peer communication
   - Deep packet inspection enabled

4. **Security Devices (40) → Management (10)**
   - Allow monitoring data transmission
   - Encrypted channels only

5. **Quarantine (60) → Isolated**
   - No internet access
   - Management access only

## 🚀 Getting Started / Configuration

### Prerequisites

1. **Network Infrastructure:**
   - Managed switch with VLAN support
   - Firewall/router with advanced features
   - Wireless access points with VLAN tagging

2. **Server Requirements:**
   - Dedicated server/VM for Home Assistant
   - Minimum 4GB RAM, 8GB+ recommended
   - SSD storage for database performance

### Initial Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/secure-smart-home-infrastructure.git
   cd secure-smart-home-infrastructure
   ```

2. **Configure network infrastructure:**
   ```bash
   ./scripts/setup/initial-network-setup.sh
   ```

3. **Set up VLANs:**
   ```bash
   ./scripts/setup/vlan-setup.sh
   ```

4. **Deploy Home Assistant:**
   ```bash
   cd config-examples/docker
   docker-compose up -d
   ```

5. **Configure monitoring:**
   ```bash
   ./scripts/setup/monitoring-setup.sh
   ```

## 🔧 Home Assistant Configuration

### Core Configuration

```yaml
# configuration.yaml
homeassistant:
  name: Secure Home
  latitude: !secret home_latitude
  longitude: !secret home_longitude
  elevation: !secret home_elevation
  unit_system: metric
  time_zone: Europe/Berlin
  
# Network security integration
network:
  trusted_networks:
    - 192.168.10.0/24  # Management VLAN
    - 192.168.20.0/24  # Trusted devices
  
# Device tracking with network monitoring
device_tracker:
  - platform: nmap_tracker
    hosts: 192.168.30.0/24  # IoT VLAN
    home_interval: 10
    consider_home: 180
```

### Security Automations

```yaml
# automations.yaml
- alias: "IoT Device Anomaly Detection"
  trigger:
    - platform: state
      entity_id: binary_sensor.network_anomaly
      to: 'on'
  action:
    - service: notify.security_team
      data:
        message: "Anomalous network activity detected on IoT VLAN"
    - service: script.isolate_suspicious_device

- alias: "New Device Detection"
  trigger:
    - platform: event
      event_type: device_tracker_new_device
  action:
    - service: script.quarantine_new_device
    - service: notify.admin
      data:
        message: "New device detected: {{ trigger.event.data.entity_id }}"
```

## 🔍 Security Monitoring

### Network Monitoring Stack

#### Suricata IDS/IPS
```yaml
# suricata.yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    IOT_NET: "[192.168.30.0/24]"
    SECURITY_NET: "[192.168.40.0/24]"

rule-files:
  - suricata.rules
  - iot-security.rules
  - custom-rules.rules

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
```

#### Custom IoT Security Rules
```bash
# iot-security.rules
alert tcp $IOT_NET any -> $EXTERNAL_NET any (msg:"IoT device unexpected outbound connection"; sid:1000001;)
alert tcp $IOT_NET any -> $IOT_NET any (msg:"IoT device lateral movement attempt"; sid:1000002;)
alert dns $IOT_NET any -> any 53 (msg:"IoT device suspicious DNS query"; content:"malware"; sid:1000003;)
```

### Device Monitoring

#### Automated Device Discovery
```bash
#!/bin/bash
# device-discovery.sh

# Scan IoT VLAN for new devices
nmap -sn 192.168.30.0/24 | grep -E "Nmap scan report" | awk '{print $5}' > current_devices.txt

# Compare with known devices
comm -23 current_devices.txt known_devices.txt > new_devices.txt

# Process new devices
while read device; do
    echo "New device detected: $device"
    # Add to quarantine VLAN
    ./quarantine-device.sh "$device"
    # Notify administrators
    ./send-alert.sh "New IoT device detected: $device"
done < new_devices.txt
```

## 🔐 Security Implementation

### Device Onboarding Process

1. **Initial Detection:**
   - New device appears on network
   - Automatically moved to quarantine VLAN
   - Basic fingerprinting performed

2. **Device Classification:**
   - Manufacturer identification via MAC OUI
   - Service discovery and port scanning
   - Behavioral analysis over 24-48 hours

3. **Security Assessment:**
   - Vulnerability scanning
   - Firmware version checking
   - Default credential testing

4. **VLAN Assignment:**
   - Based on device type and risk assessment
   - Appropriate firewall rules applied
   - Monitoring profile assigned

### Incident Response Procedures

#### Automated Response
```bash
#!/bin/bash
# isolate-device.sh

DEVICE_IP=$1
DEVICE_MAC=$2

# Move device to quarantine VLAN
vconfig add eth0 60
ip addr add 192.168.60.1/24 dev eth0.60

# Update switch port VLAN assignment
snmpset -v2c -c private switch-ip 1.3.6.1.2.1.17.7.1.4.3.1.2.$PORT i 60

# Block device in firewall
iptables -I FORWARD -s $DEVICE_IP -j DROP
iptables -I FORWARD -d $DEVICE_IP -j DROP

# Log incident
echo "$(date): Device $DEVICE_IP ($DEVICE_MAC) isolated due to security incident" >> /var/log/security-incidents.log

# Notify security team
./send-alert.sh "SECURITY INCIDENT: Device $DEVICE_IP isolated"
```

#### Manual Investigation Tools
```bash
# Capture network traffic for forensics
tcpdump -i eth0.30 -w /tmp/incident-$(date +%Y%m%d-%H%M%S).pcap host $DEVICE_IP

# Analyze device behavior
./analyze-device-traffic.sh $DEVICE_IP

# Generate incident report
./generate-incident-report.sh $DEVICE_IP
```

## 📊 Monitoring and Alerting

### Grafana Dashboards

1. **Network Overview:**
   - VLAN traffic statistics
   - Device count per VLAN
   - Bandwidth utilization

2. **Security Dashboard:**
   - IDS/IPS alerts
   - Failed authentication attempts
   - Anomalous traffic patterns

3. **Device Health:**
   - IoT device status
   - Firmware versions
   - Last seen timestamps

### Alert Conditions

```yaml
# Prometheus alerting rules
groups:
  - name: iot_security
    rules:
      - alert: IoTDeviceOffline
        expr: up{job="iot_devices"} == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "IoT device {{ $labels.instance }} is offline"

      - alert: SuspiciousTraffic
        expr: rate(suricata_alerts_total[5m]) > 0.1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High rate of security alerts detected"

      - alert: UnauthorizedVLANAccess
        expr: increase(firewall_blocked_connections[1m]) > 10
        for: 1m
        labels:
          severity: high
        annotations:
          summary: "Multiple blocked connection attempts detected"
```

## 🔧 Advanced Features

### Machine Learning Integration

```python
# anomaly_detection.py
import pandas as pd
from sklearn.ensemble import IsolationForest

class IoTAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)
        
    def train(self, network_data):
        features = ['bytes_sent', 'bytes_received', 'connection_count', 'unique_destinations']
        self.model.fit(network_data[features])
        
    def detect_anomalies(self, current_data):
        predictions = self.model.predict(current_data)
        return current_data[predictions == -1]  # Anomalies
```

### Automated Firmware Management

```bash
#!/bin/bash
# firmware-update-manager.sh

# Check for firmware updates
for device in $(cat iot_devices.txt); do
    current_version=$(snmpget -v2c -c public $device 1.3.6.1.2.1.1.1.0)
    latest_version=$(curl -s "https://api.manufacturer.com/firmware/$device_model")
    
    if [ "$current_version" != "$latest_version" ]; then
        echo "Firmware update available for $device"
        # Schedule update during maintenance window
        echo "$device $latest_version" >> pending_updates.txt
    fi
done
```

## 🔮 Potential Improvements/Future Plans

* Integration with threat intelligence feeds
* AI-powered behavioral analysis for IoT devices
* Automated penetration testing of IoT devices
* Integration with SOAR platforms for automated response
* Blockchain-based device identity management
* Advanced network micro-segmentation
* Integration with cloud security services

## ⚠️ Security Considerations

* **Regular Updates:** Keep all IoT devices updated with latest firmware
* **Default Credentials:** Change all default passwords immediately
* **Network Monitoring:** Continuously monitor for unusual traffic patterns
* **Physical Security:** Secure physical access to network infrastructure
* **Backup Strategies:** Regular backups of configurations and device states
* **Incident Response:** Have clear procedures for security incidents

## 📚 Additional Resources

* [NIST IoT Security Guidelines](https://www.nist.gov/cybersecurity/iot)
* [Home Assistant Security Best Practices](https://www.home-assistant.io/docs/configuration/securing/)
* [IoT Security Foundation Guidelines](https://www.iotsecurityfoundation.org/)
* [OWASP IoT Security Top 10](https://owasp.org/www-project-internet-of-things/)
* [Zigbee Security Best Practices](https://zigbeealliance.org/solution/zigbee/security/)