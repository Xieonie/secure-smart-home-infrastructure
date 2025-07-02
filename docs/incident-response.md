# Incident Response Guide 🚨

This guide provides comprehensive procedures for responding to security incidents in your smart home infrastructure, including detection, containment, eradication, and recovery.

## Incident Response Framework

### Incident Classification

#### Severity Levels

**CRITICAL (P1)**
- Confirmed compromise of security devices
- Data exfiltration detected
- Complete network compromise
- Safety systems compromised

**HIGH (P2)**
- Suspected device compromise
- Unusual network activity from IoT devices
- Failed authentication attempts exceeding threshold
- Malware detection

**MEDIUM (P3)**
- Policy violations
- Unauthorized network access attempts
- Device configuration changes
- Suspicious DNS queries

**LOW (P4)**
- Information gathering attempts
- Minor policy violations
- Non-critical system alerts

### Response Team Roles

**Incident Commander**
- Overall incident coordination
- Communication with stakeholders
- Decision making authority

**Security Analyst**
- Technical investigation
- Evidence collection
- Threat analysis

**Network Administrator**
- Network isolation and containment
- Infrastructure changes
- System restoration

**Communications Lead**
- Internal and external communications
- Documentation
- Stakeholder updates

## Detection and Analysis

### Automated Detection

#### Home Assistant Security Automations

```yaml
# automations.yaml
- alias: "Critical Security Alert"
  trigger:
    - platform: webhook
      webhook_id: security_alert
  condition:
    - condition: template
      value_template: "{{ trigger.json.severity|int <= 2 }}"
  action:
    - service: script.initiate_incident_response
      data:
        severity: "{{ trigger.json.severity }}"
        alert_type: "{{ trigger.json.alert_type }}"
        source_ip: "{{ trigger.json.src_ip }}"
        description: "{{ trigger.json.message }}"

- alias: "Device Compromise Detected"
  trigger:
    - platform: state
      entity_id: binary_sensor.device_compromise_detected
      to: 'on'
  action:
    - service: script.emergency_isolation
      data:
        device_ip: "{{ states.binary_sensor.device_compromise_detected.attributes.device_ip }}"
    - service: notify.security_team
      data:
        title: "🚨 DEVICE COMPROMISE DETECTED"
        message: "Device {{ states.binary_sensor.device_compromise_detected.attributes.device_ip }} shows signs of compromise"

- alias: "Lateral Movement Detection"
  trigger:
    - platform: numeric_state
      entity_id: sensor.lateral_movement_attempts
      above: 3
      for: '00:02:00'
  action:
    - service: script.lockdown_iot_vlan
    - service: notify.security_team
      data:
        title: "🔒 LATERAL MOVEMENT DETECTED"
        message: "Multiple lateral movement attempts detected on IoT VLAN"
```

#### Security Scripts

```yaml
# scripts.yaml
initiate_incident_response:
  alias: "Initiate Incident Response"
  sequence:
    - service: input_text.set_value
      target:
        entity_id: input_text.incident_id
      data:
        value: "INC-{{ now().strftime('%Y%m%d-%H%M%S') }}"
    - service: input_datetime.set_datetime
      target:
        entity_id: input_datetime.incident_start_time
      data:
        datetime: "{{ now() }}"
    - service: shell_command.create_incident_folder
      data:
        incident_id: "{{ states('input_text.incident_id') }}"
    - service: shell_command.start_evidence_collection
      data:
        incident_id: "{{ states('input_text.incident_id') }}"
        source_ip: "{{ source_ip }}"

emergency_isolation:
  alias: "Emergency Device Isolation"
  sequence:
    - service: shell_command.isolate_device
      data:
        device_ip: "{{ device_ip }}"
    - service: shell_command.capture_forensic_data
      data:
        device_ip: "{{ device_ip }}"
    - service: input_boolean.turn_on
      entity_id: input_boolean.incident_active

lockdown_iot_vlan:
  alias: "Lockdown IoT VLAN"
  sequence:
    - service: shell_command.block_iot_vlan_traffic
    - service: input_boolean.turn_on
      entity_id: input_boolean.iot_vlan_locked
    - service: light.turn_on
      entity_id: light.security_status
      data:
        color_name: red
        brightness: 255
```

### Manual Detection Procedures

#### Network Traffic Analysis

```bash
#!/bin/bash
# analyze-suspicious-traffic.sh

DEVICE_IP=$1
INCIDENT_ID=$2
ANALYSIS_DIR="/var/log/incidents/$INCIDENT_ID/analysis"

mkdir -p "$ANALYSIS_DIR"

echo "Analyzing traffic for device $DEVICE_IP"

# Capture current traffic
tcpdump -i any -w "$ANALYSIS_DIR/current_traffic.pcap" host $DEVICE_IP &
TCPDUMP_PID=$!
sleep 300  # Capture for 5 minutes
kill $TCPDUMP_PID

# Analyze captured traffic
tshark -r "$ANALYSIS_DIR/current_traffic.pcap" -T fields -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport > "$ANALYSIS_DIR/connections.txt"

# Check for suspicious patterns
echo "=== Suspicious Patterns Analysis ===" > "$ANALYSIS_DIR/suspicious_patterns.txt"

# Check for port scanning
awk '{print $3, $4}' "$ANALYSIS_DIR/connections.txt" | sort | uniq -c | sort -nr | head -20 >> "$ANALYSIS_DIR/suspicious_patterns.txt"

# Check for unusual destinations
awk '{print $2}' "$ANALYSIS_DIR/connections.txt" | grep -v "^192\.168\." | sort | uniq -c | sort -nr >> "$ANALYSIS_DIR/suspicious_patterns.txt"

# Generate summary
echo "Traffic analysis complete for $DEVICE_IP" >> "$ANALYSIS_DIR/summary.txt"
echo "Unique external destinations: $(awk '{print $2}' "$ANALYSIS_DIR/connections.txt" | grep -v "^192\.168\." | sort | uniq | wc -l)" >> "$ANALYSIS_DIR/summary.txt"
echo "Total connections: $(wc -l < "$ANALYSIS_DIR/connections.txt")" >> "$ANALYSIS_DIR/summary.txt"
```

#### Log Analysis

```bash
#!/bin/bash
# analyze-security-logs.sh

INCIDENT_ID=$1
LOG_DIR="/var/log/incidents/$INCIDENT_ID/logs"
START_TIME=$2
END_TIME=$3

mkdir -p "$LOG_DIR"

echo "Analyzing security logs for incident $INCIDENT_ID"

# Suricata alerts
jq -r 'select(.timestamp >= "'$START_TIME'" and .timestamp <= "'$END_TIME'") | [.timestamp, .alert.signature, .src_ip, .dest_ip] | @csv' /var/log/suricata/eve.json > "$LOG_DIR/suricata_alerts.csv"

# Firewall logs
grep -E "$START_TIME|$END_TIME" /var/log/pfsense.log | grep BLOCK > "$LOG_DIR/firewall_blocks.log"

# DHCP logs
grep -E "$START_TIME|$END_TIME" /var/log/dhcp.log > "$LOG_DIR/dhcp_activity.log"

# Authentication logs
grep -E "$START_TIME|$END_TIME" /var/log/auth.log > "$LOG_DIR/auth_activity.log"

# Generate timeline
echo "=== Security Event Timeline ===" > "$LOG_DIR/timeline.txt"
cat "$LOG_DIR"/*.log "$LOG_DIR"/*.csv | sort >> "$LOG_DIR/timeline.txt"
```

## Containment

### Immediate Containment

#### Device Isolation Script

```bash
#!/bin/bash
# isolate-device.sh

DEVICE_IP=$1
DEVICE_MAC=$2
INCIDENT_ID=$3

echo "Isolating device $DEVICE_IP ($DEVICE_MAC) for incident $INCIDENT_ID"

# Get switch port
SWITCH_PORT=$(snmpwalk -v2c -c public 192.168.10.1 1.3.6.1.2.1.17.4.3.1.2 | grep $DEVICE_MAC | awk '{print $1}')

if [ -n "$SWITCH_PORT" ]; then
    # Move to quarantine VLAN
    snmpset -v2c -c private 192.168.10.1 1.3.6.1.2.1.17.7.1.4.3.1.2.$SWITCH_PORT i 60
    echo "Device moved to quarantine VLAN"
else
    echo "Switch port not found, using firewall isolation"
fi

# Block device in firewall
iptables -I FORWARD -s $DEVICE_IP -j DROP
iptables -I FORWARD -d $DEVICE_IP -j DROP
iptables -I INPUT -s $DEVICE_IP -j DROP

# Log isolation
echo "$(date): Device $DEVICE_IP ($DEVICE_MAC) isolated for incident $INCIDENT_ID" >> /var/log/incident-actions.log

# Notify Home Assistant
curl -X POST http://192.168.10.50:8123/api/webhook/device_isolated \
     -H "Content-Type: application/json" \
     -d "{\"device_ip\":\"$DEVICE_IP\",\"device_mac\":\"$DEVICE_MAC\",\"incident_id\":\"$INCIDENT_ID\",\"timestamp\":\"$(date -Iseconds)\"}"

echo "Device isolation complete"
```

#### Network Segmentation

```bash
#!/bin/bash
# emergency-network-segmentation.sh

INCIDENT_ID=$1
AFFECTED_VLAN=$2

echo "Implementing emergency network segmentation for incident $INCIDENT_ID"

case $AFFECTED_VLAN in
    "iot")
        # Block IoT VLAN from accessing other networks
        iptables -I FORWARD -s 192.168.30.0/24 -d 192.168.10.0/24 -j DROP
        iptables -I FORWARD -s 192.168.30.0/24 -d 192.168.20.0/24 -j DROP
        iptables -I FORWARD -s 192.168.30.0/24 -d 192.168.40.0/24 -j DROP
        echo "IoT VLAN isolated from other networks"
        ;;
    "security")
        # Isolate security VLAN
        iptables -I FORWARD -s 192.168.40.0/24 -d 192.168.10.0/24 -j DROP
        iptables -I FORWARD -s 192.168.40.0/24 -d 192.168.20.0/24 -j DROP
        iptables -I FORWARD -s 192.168.40.0/24 -d 192.168.30.0/24 -j DROP
        echo "Security VLAN isolated"
        ;;
    "all")
        # Complete network lockdown
        iptables -P FORWARD DROP
        iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.10.0/24 -j ACCEPT
        echo "Complete network lockdown activated"
        ;;
esac

# Log action
echo "$(date): Emergency segmentation applied to $AFFECTED_VLAN for incident $INCIDENT_ID" >> /var/log/incident-actions.log
```

### Evidence Collection

#### Forensic Data Collection

```bash
#!/bin/bash
# collect-forensic-data.sh

DEVICE_IP=$1
INCIDENT_ID=$2
EVIDENCE_DIR="/var/log/incidents/$INCIDENT_ID/evidence"

mkdir -p "$EVIDENCE_DIR"

echo "Collecting forensic evidence for device $DEVICE_IP"

# Network traffic capture
tcpdump -i any -w "$EVIDENCE_DIR/traffic_capture_$(date +%Y%m%d_%H%M%S).pcap" host $DEVICE_IP &
TCPDUMP_PID=$!

# Memory dump (if accessible via SNMP)
snmpwalk -v2c -c public $DEVICE_IP 1.3.6.1.2.1.25.2.3.1.6 > "$EVIDENCE_DIR/memory_info.txt"

# System information
nmap -O -sV $DEVICE_IP > "$EVIDENCE_DIR/system_info.txt"

# Configuration backup (if possible)
curl -s http://$DEVICE_IP/config.xml > "$EVIDENCE_DIR/device_config.xml" 2>/dev/null

# Log current connections
netstat -an | grep $DEVICE_IP > "$EVIDENCE_DIR/active_connections.txt"

# ARP table
arp -a | grep $DEVICE_IP > "$EVIDENCE_DIR/arp_entry.txt"

# Stop traffic capture after 10 minutes
sleep 600
kill $TCPDUMP_PID

# Create evidence hash
find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/evidence_hashes.txt"

echo "Forensic evidence collection complete"
```

#### Chain of Custody

```bash
#!/bin/bash
# create-chain-of-custody.sh

INCIDENT_ID=$1
EVIDENCE_DIR="/var/log/incidents/$INCIDENT_ID/evidence"
CUSTODY_FILE="$EVIDENCE_DIR/chain_of_custody.txt"

cat > "$CUSTODY_FILE" << EOF
CHAIN OF CUSTODY RECORD
======================

Incident ID: $INCIDENT_ID
Date/Time: $(date)
Collected by: $(whoami)
System: $(hostname)

Evidence Items:
EOF

# List all evidence files
find "$EVIDENCE_DIR" -type f -not -name "chain_of_custody.txt" | while read file; do
    echo "- $(basename "$file") - $(sha256sum "$file" | cut -d' ' -f1)" >> "$CUSTODY_FILE"
done

cat >> "$CUSTODY_FILE" << EOF

Custody Transfer Log:
$(date) - Evidence collected by $(whoami)
EOF

echo "Chain of custody record created"
```

## Eradication and Recovery

### Malware Removal

```bash
#!/bin/bash
# eradicate-malware.sh

DEVICE_IP=$1
INCIDENT_ID=$2

echo "Starting malware eradication for device $DEVICE_IP"

# Attempt to connect and clean (if device supports it)
if ping -c 1 $DEVICE_IP > /dev/null; then
    # Try common IoT device reset procedures
    echo "Attempting device reset..."
    
    # HTTP-based reset (common for many IoT devices)
    curl -X POST http://$DEVICE_IP/reset -d "factory_reset=1" 2>/dev/null
    
    # SNMP-based reset
    snmpset -v2c -c private $DEVICE_IP 1.3.6.1.2.1.1.9.1.4.1 i 1 2>/dev/null
    
    # Wait for device to restart
    sleep 60
    
    # Verify device is clean
    nmap --script vuln $DEVICE_IP > "/var/log/incidents/$INCIDENT_ID/post_cleanup_scan.txt"
fi

echo "Malware eradication attempt complete"
```

### System Recovery

```bash
#!/bin/bash
# recover-system.sh

INCIDENT_ID=$1
AFFECTED_SYSTEMS=$2

echo "Starting system recovery for incident $INCIDENT_ID"

# Restore network connectivity
echo "Restoring network connectivity..."
iptables -F FORWARD
iptables -P FORWARD ACCEPT

# Restore VLAN configurations
./restore-vlan-config.sh

# Update security rules
echo "Updating security rules..."
suricata-update
systemctl reload suricata

# Update threat intelligence
./update-threat-intelligence.sh

# Verify system integrity
echo "Verifying system integrity..."
./verify-system-integrity.sh

# Generate recovery report
cat > "/var/log/incidents/$INCIDENT_ID/recovery_report.txt" << EOF
System Recovery Report
=====================

Incident ID: $INCIDENT_ID
Recovery Date: $(date)
Affected Systems: $AFFECTED_SYSTEMS

Recovery Actions:
- Network connectivity restored
- VLAN configurations restored
- Security rules updated
- Threat intelligence updated
- System integrity verified

Recovery Status: COMPLETE
EOF

echo "System recovery complete"
```

## Post-Incident Activities

### Lessons Learned

```bash
#!/bin/bash
# generate-lessons-learned.sh

INCIDENT_ID=$1
INCIDENT_DIR="/var/log/incidents/$INCIDENT_ID"

cat > "$INCIDENT_DIR/lessons_learned.md" << EOF
# Lessons Learned Report

## Incident Summary
- **Incident ID:** $INCIDENT_ID
- **Date:** $(date)
- **Duration:** [TO BE FILLED]
- **Severity:** [TO BE FILLED]

## What Happened
[Detailed description of the incident]

## Timeline
[Key events and response actions]

## What Went Well
- [Positive aspects of the response]

## What Could Be Improved
- [Areas for improvement]

## Action Items
- [ ] [Specific action item 1]
- [ ] [Specific action item 2]

## Recommendations
- [Security improvements]
- [Process improvements]
- [Technology improvements]
EOF

echo "Lessons learned template created at $INCIDENT_DIR/lessons_learned.md"
```

### Security Improvements

```python
#!/usr/bin/env python3
# implement-security-improvements.py

import json
import sys
from pathlib import Path

class SecurityImprovement:
    def __init__(self, incident_id):
        self.incident_id = incident_id
        self.incident_dir = Path(f"/var/log/incidents/{incident_id}")
        
    def analyze_incident(self):
        """Analyze incident data to identify security gaps"""
        improvements = []
        
        # Analyze attack vectors
        if self.check_file_exists("analysis/attack_vector.txt"):
            improvements.extend(self.analyze_attack_vectors())
        
        # Analyze detection gaps
        if self.check_file_exists("analysis/detection_gaps.txt"):
            improvements.extend(self.analyze_detection_gaps())
        
        # Analyze response effectiveness
        improvements.extend(self.analyze_response_effectiveness())
        
        return improvements
    
    def analyze_attack_vectors(self):
        improvements = []
        
        # Read attack vector analysis
        with open(self.incident_dir / "analysis/attack_vector.txt") as f:
            content = f.read()
        
        if "default credentials" in content.lower():
            improvements.append({
                "type": "policy",
                "description": "Implement mandatory credential change policy",
                "priority": "high"
            })
        
        if "unpatched vulnerability" in content.lower():
            improvements.append({
                "type": "process",
                "description": "Enhance vulnerability management process",
                "priority": "high"
            })
        
        return improvements
    
    def analyze_detection_gaps(self):
        improvements = []
        
        # Check detection timing
        timeline_file = self.incident_dir / "timeline.txt"
        if timeline_file.exists():
            with open(timeline_file) as f:
                timeline = f.read()
            
            # If detection took too long, suggest improvements
            if "detection_delay" in timeline:
                improvements.append({
                    "type": "technology",
                    "description": "Implement additional monitoring sensors",
                    "priority": "medium"
                })
        
        return improvements
    
    def analyze_response_effectiveness(self):
        improvements = []
        
        # Check response time
        response_log = self.incident_dir / "response_log.txt"
        if response_log.exists():
            improvements.append({
                "type": "process",
                "description": "Review and update incident response procedures",
                "priority": "medium"
            })
        
        return improvements
    
    def check_file_exists(self, filename):
        return (self.incident_dir / filename).exists()
    
    def generate_improvement_plan(self):
        improvements = self.analyze_incident()
        
        plan = {
            "incident_id": self.incident_id,
            "improvements": improvements,
            "generated_date": str(datetime.now()),
            "status": "pending"
        }
        
        # Save improvement plan
        with open(self.incident_dir / "improvement_plan.json", 'w') as f:
            json.dump(plan, f, indent=2)
        
        return plan

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: implement-security-improvements.py <incident_id>")
        sys.exit(1)
    
    incident_id = sys.argv[1]
    improver = SecurityImprovement(incident_id)
    plan = improver.generate_improvement_plan()
    
    print(f"Security improvement plan generated for incident {incident_id}")
    print(f"Found {len(plan['improvements'])} improvement opportunities")
```

## Incident Response Playbooks

### Playbook: IoT Device Compromise

```yaml
# playbook_iot_compromise.yaml
name: "IoT Device Compromise Response"
trigger: "Device showing signs of compromise"
severity: "HIGH"

steps:
  1:
    action: "Immediate Isolation"
    commands:
      - "./isolate-device.sh {{ device_ip }} {{ device_mac }} {{ incident_id }}"
    timeout: "2 minutes"
    
  2:
    action: "Evidence Collection"
    commands:
      - "./collect-forensic-data.sh {{ device_ip }} {{ incident_id }}"
    timeout: "10 minutes"
    
  3:
    action: "Threat Analysis"
    commands:
      - "./analyze-device-behavior.sh {{ device_ip }} {{ incident_id }}"
    timeout: "30 minutes"
    
  4:
    action: "Containment Verification"
    commands:
      - "./verify-isolation.sh {{ device_ip }}"
    timeout: "5 minutes"
    
  5:
    action: "Eradication"
    commands:
      - "./eradicate-malware.sh {{ device_ip }} {{ incident_id }}"
    timeout: "15 minutes"
    
  6:
    action: "Recovery"
    commands:
      - "./recover-device.sh {{ device_ip }} {{ incident_id }}"
    timeout: "20 minutes"
```

### Playbook: Network Intrusion

```yaml
# playbook_network_intrusion.yaml
name: "Network Intrusion Response"
trigger: "Unauthorized network access detected"
severity: "CRITICAL"

steps:
  1:
    action: "Emergency Segmentation"
    commands:
      - "./emergency-network-segmentation.sh {{ incident_id }} {{ affected_vlan }}"
    timeout: "1 minute"
    
  2:
    action: "Traffic Analysis"
    commands:
      - "./analyze-suspicious-traffic.sh {{ source_ip }} {{ incident_id }}"
    timeout: "15 minutes"
    
  3:
    action: "Log Analysis"
    commands:
      - "./analyze-security-logs.sh {{ incident_id }} {{ start_time }} {{ end_time }}"
    timeout: "20 minutes"
    
  4:
    action: "Threat Hunting"
    commands:
      - "./hunt-for-threats.sh {{ incident_id }}"
    timeout: "60 minutes"
    
  5:
    action: "System Hardening"
    commands:
      - "./emergency-hardening.sh {{ incident_id }}"
    timeout: "30 minutes"
```

## Communication Templates

### Security Alert Notification

```bash
# send-security-alert.sh
INCIDENT_ID=$1
SEVERITY=$2
DESCRIPTION=$3

# Email notification
cat > /tmp/security_alert_email.txt << EOF
Subject: [SECURITY ALERT - $SEVERITY] Incident $INCIDENT_ID

A security incident has been detected in the smart home infrastructure.

Incident Details:
- Incident ID: $INCIDENT_ID
- Severity: $SEVERITY
- Description: $DESCRIPTION
- Detection Time: $(date)
- Response Status: IN PROGRESS

Immediate actions taken:
- Affected systems isolated
- Evidence collection initiated
- Security team notified

Next steps:
- Detailed investigation in progress
- Updates will be provided every 30 minutes

For questions, contact the security team.
EOF

# Send email
mail -s "[SECURITY ALERT - $SEVERITY] Incident $INCIDENT_ID" security-team@domain.com < /tmp/security_alert_email.txt

# Home Assistant notification
curl -X POST http://192.168.10.50:8123/api/webhook/security_notification \
     -H "Content-Type: application/json" \
     -d "{\"incident_id\":\"$INCIDENT_ID\",\"severity\":\"$SEVERITY\",\"description\":\"$DESCRIPTION\",\"timestamp\":\"$(date -Iseconds)\"}"
```

## Metrics and KPIs

### Incident Response Metrics

```python
# incident_metrics.py

class IncidentMetrics:
    def __init__(self):
        self.incidents_dir = Path("/var/log/incidents")
    
    def calculate_response_metrics(self):
        metrics = {
            "mean_time_to_detection": 0,
            "mean_time_to_containment": 0,
            "mean_time_to_recovery": 0,
            "incident_count_by_severity": {},
            "false_positive_rate": 0
        }
        
        # Calculate metrics from incident logs
        for incident_dir in self.incidents_dir.iterdir():
            if incident_dir.is_dir():
                incident_data = self.parse_incident_data(incident_dir)
                # Update metrics...
        
        return metrics
    
    def generate_monthly_report(self):
        metrics = self.calculate_response_metrics()
        
        report = f"""
        Smart Home Security Incident Response Report
        ==========================================
        
        Period: {datetime.now().strftime('%B %Y')}
        
        Key Metrics:
        - Mean Time to Detection: {metrics['mean_time_to_detection']} minutes
        - Mean Time to Containment: {metrics['mean_time_to_containment']} minutes
        - Mean Time to Recovery: {metrics['mean_time_to_recovery']} minutes
        
        Incident Summary:
        - Total Incidents: {sum(metrics['incident_count_by_severity'].values())}
        - Critical: {metrics['incident_count_by_severity'].get('CRITICAL', 0)}
        - High: {metrics['incident_count_by_severity'].get('HIGH', 0)}
        - Medium: {metrics['incident_count_by_severity'].get('MEDIUM', 0)}
        - Low: {metrics['incident_count_by_severity'].get('LOW', 0)}
        
        False Positive Rate: {metrics['false_positive_rate']}%
        """
        
        return report
```

## Additional Resources

- [NIST Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Response Process](https://www.sans.org/white-papers/1901/)
- [IoT Incident Response Best Practices](https://www.iotsecurityfoundation.org/)
- [Home Network Security Guidelines](https://www.cisa.gov/uscert/ncas/tips/ST15-002)