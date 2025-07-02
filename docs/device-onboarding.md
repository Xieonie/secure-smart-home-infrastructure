# Device Onboarding Guide 📱

This guide covers the secure onboarding process for new IoT devices in your smart home infrastructure, ensuring proper security assessment and VLAN assignment.

## Overview

The device onboarding process follows a zero-trust approach where new devices are automatically quarantined, assessed, and then assigned to appropriate network segments based on their security profile and functionality.

## Onboarding Workflow

### 1. Device Detection

When a new device connects to the network:

```bash
#!/bin/bash
# device-detection.sh

# Monitor for new MAC addresses
while true; do
    # Scan all VLANs for new devices
    nmap -sn 192.168.0.0/16 | grep -E "Nmap scan report" | awk '{print $5}' > /tmp/current_devices.txt
    
    # Compare with known devices
    comm -23 /tmp/current_devices.txt /etc/security/known_devices.txt > /tmp/new_devices.txt
    
    if [ -s /tmp/new_devices.txt ]; then
        while read device; do
            echo "New device detected: $device"
            ./quarantine-new-device.sh "$device"
        done < /tmp/new_devices.txt
    fi
    
    sleep 60
done
```

### 2. Automatic Quarantine

New devices are immediately moved to the quarantine VLAN:

```bash
#!/bin/bash
# quarantine-new-device.sh

DEVICE_IP=$1
DEVICE_MAC=$(arp -n $DEVICE_IP | awk '{print $3}')

# Get switch port for device
SWITCH_PORT=$(snmpwalk -v2c -c public 192.168.10.1 1.3.6.1.2.1.17.4.3.1.2 | grep $DEVICE_MAC | awk '{print $1}')

# Move to quarantine VLAN (VLAN 60)
snmpset -v2c -c private 192.168.10.1 1.3.6.1.2.1.17.7.1.4.3.1.2.$SWITCH_PORT i 60

# Log the action
echo "$(date): Device $DEVICE_IP ($DEVICE_MAC) moved to quarantine VLAN" >> /var/log/device-onboarding.log

# Start assessment process
./assess-device.sh "$DEVICE_IP" "$DEVICE_MAC" &
```

### 3. Device Assessment

Comprehensive security assessment of the quarantined device:

```bash
#!/bin/bash
# assess-device.sh

DEVICE_IP=$1
DEVICE_MAC=$2
ASSESSMENT_DIR="/var/log/device-assessments/$DEVICE_MAC"

mkdir -p "$ASSESSMENT_DIR"

echo "Starting assessment for device $DEVICE_IP ($DEVICE_MAC)"

# Basic connectivity test
ping -c 3 $DEVICE_IP > "$ASSESSMENT_DIR/connectivity.txt"

# Port scan
nmap -sS -O -sV -p- $DEVICE_IP > "$ASSESSMENT_DIR/port_scan.txt"

# Service enumeration
nmap -sC -sV $DEVICE_IP > "$ASSESSMENT_DIR/service_enum.txt"

# Vulnerability scan
nmap --script vuln $DEVICE_IP > "$ASSESSMENT_DIR/vulnerability_scan.txt"

# Manufacturer identification
OUI=$(echo $DEVICE_MAC | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
MANUFACTURER=$(grep $OUI /etc/security/oui.txt | cut -d$'\t' -f3)
echo "Manufacturer: $MANUFACTURER" > "$ASSESSMENT_DIR/manufacturer.txt"

# Default credential check
./check-default-credentials.sh $DEVICE_IP > "$ASSESSMENT_DIR/default_creds.txt"

# Traffic analysis (monitor for 24 hours)
tcpdump -i any -w "$ASSESSMENT_DIR/traffic_$(date +%Y%m%d).pcap" host $DEVICE_IP &
TCPDUMP_PID=$!
echo $TCPDUMP_PID > "$ASSESSMENT_DIR/tcpdump.pid"

# Schedule traffic analysis stop
echo "./stop-traffic-capture.sh $DEVICE_MAC" | at now + 24 hours

# Generate risk assessment
./generate-risk-assessment.sh "$DEVICE_IP" "$DEVICE_MAC"
```

### 4. Risk Assessment

Automated risk scoring based on assessment results:

```python
#!/usr/bin/env python3
# generate-risk-assessment.py

import json
import sys
import re
from pathlib import Path

class DeviceRiskAssessment:
    def __init__(self, device_ip, device_mac):
        self.device_ip = device_ip
        self.device_mac = device_mac
        self.assessment_dir = Path(f"/var/log/device-assessments/{device_mac}")
        self.risk_score = 0
        self.risk_factors = []
        
    def assess_risk(self):
        # Check for open ports
        self.check_open_ports()
        
        # Check for vulnerabilities
        self.check_vulnerabilities()
        
        # Check for default credentials
        self.check_default_credentials()
        
        # Check manufacturer reputation
        self.check_manufacturer()
        
        # Analyze network behavior
        self.analyze_network_behavior()
        
        return self.generate_report()
    
    def check_open_ports(self):
        port_scan_file = self.assessment_dir / "port_scan.txt"
        if port_scan_file.exists():
            with open(port_scan_file) as f:
                content = f.read()
                
            # Count open ports
            open_ports = len(re.findall(r'(\d+)/tcp\s+open', content))
            
            if open_ports > 10:
                self.risk_score += 30
                self.risk_factors.append(f"High number of open ports: {open_ports}")
            elif open_ports > 5:
                self.risk_score += 15
                self.risk_factors.append(f"Moderate number of open ports: {open_ports}")
            
            # Check for dangerous services
            dangerous_services = ['telnet', 'ftp', 'rsh', 'rlogin']
            for service in dangerous_services:
                if service in content.lower():
                    self.risk_score += 25
                    self.risk_factors.append(f"Dangerous service detected: {service}")
    
    def check_vulnerabilities(self):
        vuln_file = self.assessment_dir / "vulnerability_scan.txt"
        if vuln_file.exists():
            with open(vuln_file) as f:
                content = f.read()
            
            # Count vulnerabilities by severity
            critical_vulns = len(re.findall(r'CRITICAL', content, re.IGNORECASE))
            high_vulns = len(re.findall(r'HIGH', content, re.IGNORECASE))
            medium_vulns = len(re.findall(r'MEDIUM', content, re.IGNORECASE))
            
            self.risk_score += critical_vulns * 40
            self.risk_score += high_vulns * 25
            self.risk_score += medium_vulns * 10
            
            if critical_vulns > 0:
                self.risk_factors.append(f"Critical vulnerabilities: {critical_vulns}")
            if high_vulns > 0:
                self.risk_factors.append(f"High severity vulnerabilities: {high_vulns}")
    
    def check_default_credentials(self):
        creds_file = self.assessment_dir / "default_creds.txt"
        if creds_file.exists():
            with open(creds_file) as f:
                content = f.read()
            
            if "SUCCESS" in content:
                self.risk_score += 50
                self.risk_factors.append("Default credentials found")
    
    def check_manufacturer(self):
        manufacturer_file = self.assessment_dir / "manufacturer.txt"
        if manufacturer_file.exists():
            with open(manufacturer_file) as f:
                manufacturer = f.read().strip().replace("Manufacturer: ", "")
            
            # Known problematic manufacturers
            high_risk_manufacturers = ["Unknown", "Generic", "Unregistered"]
            if any(risk_mfg in manufacturer for risk_mfg in high_risk_manufacturers):
                self.risk_score += 20
                self.risk_factors.append(f"Unknown or generic manufacturer: {manufacturer}")
    
    def analyze_network_behavior(self):
        # This would analyze the captured traffic
        # For now, we'll do a simple check
        traffic_file = self.assessment_dir / f"traffic_{self.get_today_date()}.pcap"
        if traffic_file.exists():
            # Use tshark to analyze traffic
            import subprocess
            
            # Check for suspicious destinations
            result = subprocess.run([
                'tshark', '-r', str(traffic_file), '-T', 'fields', '-e', 'ip.dst'
            ], capture_output=True, text=True)
            
            destinations = set(result.stdout.strip().split('\n'))
            external_destinations = [ip for ip in destinations if not ip.startswith('192.168.')]
            
            if len(external_destinations) > 10:
                self.risk_score += 15
                self.risk_factors.append(f"High number of external connections: {len(external_destinations)}")
    
    def get_today_date(self):
        from datetime import datetime
        return datetime.now().strftime('%Y%m%d')
    
    def generate_report(self):
        # Determine risk level
        if self.risk_score >= 80:
            risk_level = "CRITICAL"
            recommended_vlan = "quarantine"
        elif self.risk_score >= 60:
            risk_level = "HIGH"
            recommended_vlan = "quarantine"
        elif self.risk_score >= 40:
            risk_level = "MEDIUM"
            recommended_vlan = "iot_restricted"
        elif self.risk_score >= 20:
            risk_level = "LOW"
            recommended_vlan = "iot"
        else:
            risk_level = "MINIMAL"
            recommended_vlan = "iot"
        
        report = {
            "device_ip": self.device_ip,
            "device_mac": self.device_mac,
            "risk_score": self.risk_score,
            "risk_level": risk_level,
            "risk_factors": self.risk_factors,
            "recommended_vlan": recommended_vlan,
            "assessment_timestamp": self.get_today_date()
        }
        
        # Save report
        report_file = self.assessment_dir / "risk_assessment.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: generate-risk-assessment.py <device_ip> <device_mac>")
        sys.exit(1)
    
    device_ip = sys.argv[1]
    device_mac = sys.argv[2]
    
    assessor = DeviceRiskAssessment(device_ip, device_mac)
    report = assessor.assess_risk()
    
    print(f"Risk Assessment Complete:")
    print(f"Device: {device_ip} ({device_mac})")
    print(f"Risk Level: {report['risk_level']}")
    print(f"Risk Score: {report['risk_score']}")
    print(f"Recommended VLAN: {report['recommended_vlan']}")
```

### 5. VLAN Assignment

Based on risk assessment, assign device to appropriate VLAN:

```bash
#!/bin/bash
# assign-device-vlan.sh

DEVICE_IP=$1
DEVICE_MAC=$2
ASSESSMENT_FILE="/var/log/device-assessments/$DEVICE_MAC/risk_assessment.json"

if [ ! -f "$ASSESSMENT_FILE" ]; then
    echo "Assessment file not found for device $DEVICE_MAC"
    exit 1
fi

# Parse risk assessment
RECOMMENDED_VLAN=$(jq -r '.recommended_vlan' "$ASSESSMENT_FILE")
RISK_LEVEL=$(jq -r '.risk_level' "$ASSESSMENT_FILE")

# Map VLAN names to VLAN IDs
case $RECOMMENDED_VLAN in
    "iot")
        VLAN_ID=30
        ;;
    "iot_restricted")
        VLAN_ID=35
        ;;
    "security")
        VLAN_ID=40
        ;;
    "quarantine")
        VLAN_ID=60
        ;;
    *)
        echo "Unknown VLAN recommendation: $RECOMMENDED_VLAN"
        VLAN_ID=60  # Default to quarantine
        ;;
esac

# Get switch port
SWITCH_PORT=$(snmpwalk -v2c -c public 192.168.10.1 1.3.6.1.2.1.17.4.3.1.2 | grep $DEVICE_MAC | awk '{print $1}')

# Assign VLAN
snmpset -v2c -c private 192.168.10.1 1.3.6.1.2.1.17.7.1.4.3.1.2.$SWITCH_PORT i $VLAN_ID

# Update device database
echo "$DEVICE_MAC,$DEVICE_IP,$RECOMMENDED_VLAN,$RISK_LEVEL,$(date)" >> /etc/security/device_database.csv

# Configure firewall rules for the device
./configure-device-firewall.sh "$DEVICE_IP" "$RECOMMENDED_VLAN"

# Notify Home Assistant
curl -X POST http://192.168.10.50:8123/api/webhook/device_onboarded \
     -H "Content-Type: application/json" \
     -d "{\"device_ip\":\"$DEVICE_IP\",\"device_mac\":\"$DEVICE_MAC\",\"vlan\":\"$RECOMMENDED_VLAN\",\"risk_level\":\"$RISK_LEVEL\"}"

echo "Device $DEVICE_MAC assigned to VLAN $VLAN_ID ($RECOMMENDED_VLAN) with risk level $RISK_LEVEL"
```

## Device Categories and VLAN Assignment

### Device Classification

```python
# device_classifier.py

class DeviceClassifier:
    def __init__(self):
        self.device_signatures = {
            'security_camera': {
                'ports': [80, 443, 554, 8080],
                'services': ['rtsp', 'http'],
                'manufacturers': ['Hikvision', 'Dahua', 'Axis', 'Ubiquiti']
            },
            'smart_speaker': {
                'ports': [80, 443, 4070, 55443],
                'services': ['http', 'https'],
                'manufacturers': ['Amazon', 'Google', 'Apple']
            },
            'smart_light': {
                'ports': [80, 443],
                'services': ['http'],
                'manufacturers': ['Philips', 'LIFX', 'TP-Link']
            },
            'smart_thermostat': {
                'ports': [80, 443, 8080],
                'services': ['http', 'https'],
                'manufacturers': ['Nest', 'Honeywell', 'Ecobee']
            }
        }
    
    def classify_device(self, device_info):
        open_ports = device_info.get('open_ports', [])
        services = device_info.get('services', [])
        manufacturer = device_info.get('manufacturer', '')
        
        scores = {}
        
        for device_type, signature in self.device_signatures.items():
            score = 0
            
            # Check port matches
            port_matches = len(set(open_ports) & set(signature['ports']))
            score += port_matches * 10
            
            # Check service matches
            service_matches = len(set(services) & set(signature['services']))
            score += service_matches * 15
            
            # Check manufacturer
            if any(mfg in manufacturer for mfg in signature['manufacturers']):
                score += 25
            
            scores[device_type] = score
        
        # Return the device type with highest score
        if scores:
            return max(scores, key=scores.get)
        else:
            return 'unknown'
```

### VLAN Assignment Rules

| Device Type | Risk Level | VLAN | Network Access |
|-------------|------------|------|----------------|
| Security Camera | LOW-MEDIUM | Security (40) | Local network only |
| Smart Speaker | MEDIUM | IoT Restricted (35) | Limited internet |
| Smart Light | LOW | IoT (30) | Local + cloud services |
| Smart Thermostat | LOW-MEDIUM | IoT (30) | Local + cloud services |
| Unknown Device | ANY | Quarantine (60) | No network access |
| High Risk Device | HIGH-CRITICAL | Quarantine (60) | No network access |

## Monitoring and Maintenance

### Continuous Assessment

```bash
#!/bin/bash
# continuous-assessment.sh

# Re-assess devices periodically
while read line; do
    DEVICE_MAC=$(echo $line | cut -d, -f1)
    DEVICE_IP=$(echo $line | cut -d, -f2)
    LAST_ASSESSMENT=$(echo $line | cut -d, -f5)
    
    # Check if assessment is older than 30 days
    if [ $(date -d "$LAST_ASSESSMENT" +%s) -lt $(date -d "30 days ago" +%s) ]; then
        echo "Re-assessing device $DEVICE_MAC"
        ./assess-device.sh "$DEVICE_IP" "$DEVICE_MAC"
    fi
done < /etc/security/device_database.csv
```

### Device Health Monitoring

```yaml
# Home Assistant device monitoring
sensor:
  - platform: command_line
    name: "Quarantined Devices"
    command: "grep -c ',quarantine,' /etc/security/device_database.csv"
    scan_interval: 300

  - platform: command_line
    name: "High Risk Devices"
    command: "grep -c ',HIGH\\|,CRITICAL,' /etc/security/device_database.csv"
    scan_interval: 300

automation:
  - alias: "Device Assessment Complete"
    trigger:
      - platform: webhook
        webhook_id: device_onboarded
    action:
      - service: notify.admin
        data:
          title: "Device Onboarding Complete"
          message: |
            Device {{ trigger.json.device_ip }} ({{ trigger.json.device_mac }})
            Risk Level: {{ trigger.json.risk_level }}
            Assigned to: {{ trigger.json.vlan }} VLAN
```

## Security Best Practices

### 1. Zero Trust Approach
- All new devices start in quarantine
- Comprehensive assessment before network access
- Continuous monitoring and re-assessment

### 2. Defense in Depth
- Network segmentation
- Application-level security
- Device-level hardening

### 3. Automated Response
- Immediate quarantine of suspicious devices
- Automated risk assessment
- Dynamic VLAN assignment

### 4. Continuous Improvement
- Regular review of assessment criteria
- Update device signatures
- Refine risk scoring algorithms

## Troubleshooting

### Common Issues

1. **Device Not Detected:**
   ```bash
   # Check network scanning
   nmap -sn 192.168.0.0/16
   
   # Verify DHCP logs
   tail -f /var/log/dhcp.log
   ```

2. **Assessment Fails:**
   ```bash
   # Check connectivity
   ping -c 3 <device_ip>
   
   # Verify SNMP access to switch
   snmpwalk -v2c -c public 192.168.10.1 1.3.6.1.2.1.1.1.0
   ```

3. **VLAN Assignment Issues:**
   ```bash
   # Check switch configuration
   snmpget -v2c -c public 192.168.10.1 1.3.6.1.2.1.17.7.1.4.3.1.2.<port>
   
   # Verify firewall rules
   iptables -L -n -v
   ```

## Additional Resources

- [NIST IoT Device Security Guidelines](https://www.nist.gov/cybersecurity/iot)
- [IoT Security Foundation Device Assessment](https://www.iotsecurityfoundation.org/)
- [OWASP IoT Security Testing Guide](https://owasp.org/www-project-iot-security-testing-guide/)