# Home Assistant Setup Guide 🏠

This guide covers the installation and configuration of Home Assistant for a secure smart home infrastructure with proper network segmentation and security controls.

## Prerequisites

- Ubuntu Server 20.04+ or similar Linux distribution
- Docker and Docker Compose installed
- Network infrastructure with VLAN support configured
- Static IP address assigned to Home Assistant server

## Installation

### Docker Compose Setup

1. **Create directory structure:**
   ```bash
   mkdir -p /opt/homeassistant/{config,media,backups}
   sudo chown -R 1000:1000 /opt/homeassistant
   ```

2. **Deploy Home Assistant:**
   ```bash
   cd /opt/homeassistant
   docker-compose up -d
   ```

3. **Initial configuration:**
   - Access Home Assistant at `http://your-server-ip:8123`
   - Complete the onboarding process
   - Create admin user account

## Network Configuration

### VLAN Integration

Configure Home Assistant to work with your VLAN setup:

```yaml
# configuration.yaml
homeassistant:
  name: Secure Home
  latitude: !secret home_latitude
  longitude: !secret home_longitude
  elevation: !secret home_elevation
  unit_system: metric
  time_zone: Europe/Berlin
  
  # Trusted networks for authentication bypass
  trusted_networks:
    - 192.168.10.0/24  # Management VLAN
    - 192.168.20.0/24  # Trusted devices VLAN
  
  # Allowlist external directories
  allowlist_external_dirs:
    - /config
    - /media
    - /backups

# Network discovery for IoT devices
discovery:
  ignore:
    - apple_tv
    - roku

# Device tracking
device_tracker:
  - platform: nmap_tracker
    hosts: 
      - 192.168.30.0/24  # IoT VLAN
      - 192.168.40.0/24  # Security devices VLAN
    home_interval: 10
    consider_home: 180
    scan_options: " --privileged -sS "
```

### Firewall Rules

Ensure proper firewall rules are configured:

```bash
# Allow Home Assistant access to IoT devices
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.30.0/24 -p tcp --dport 80,443,8080 -j ACCEPT
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.40.0/24 -p tcp --dport 80,443,554 -j ACCEPT

# Allow IoT devices to communicate with Home Assistant
iptables -A FORWARD -s 192.168.30.0/24 -d 192.168.10.0/24 -p tcp --dport 8123 -j ACCEPT
iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.10.0/24 -p tcp --dport 8123 -j ACCEPT
```

## Security Configuration

### Authentication

1. **Enable two-factor authentication:**
   ```yaml
   # configuration.yaml
   auth:
     providers:
       - type: homeassistant
       - type: trusted_networks
         trusted_networks:
           - 192.168.10.0/24
   ```

2. **Configure user accounts:**
   - Create separate accounts for different users
   - Assign appropriate permissions
   - Enable 2FA for all accounts

### SSL/TLS Configuration

```yaml
# configuration.yaml
http:
  ssl_certificate: /ssl/fullchain.pem
  ssl_key: /ssl/privkey.pem
  server_port: 8123
  cors_allowed_origins:
    - https://cast.home-assistant.io
  use_x_forwarded_for: true
  trusted_proxies:
    - 192.168.10.1  # Reverse proxy IP
```

## Integration Setup

### Zigbee2MQTT Integration

```yaml
# configuration.yaml
mqtt:
  broker: localhost
  port: 1883
  username: !secret mqtt_username
  password: !secret mqtt_password
  discovery: true
  discovery_prefix: homeassistant
```

### Security Integrations

```yaml
# configuration.yaml
# Network monitoring integration
sensor:
  - platform: command_line
    name: "Network Anomalies"
    command: "grep -c 'ANOMALY' /var/log/suricata/eve.json | tail -1"
    scan_interval: 60

# Firewall monitoring
  - platform: command_line
    name: "Blocked Connections"
    command: "grep -c 'BLOCK' /var/log/pfsense.log | tail -1"
    scan_interval: 300

binary_sensor:
  - platform: template
    sensors:
      network_anomaly:
        friendly_name: "Network Anomaly Detected"
        value_template: "{{ states('sensor.network_anomalies')|int > 0 }}"
```

## Automation Examples

### Security Automations

```yaml
# automations.yaml
- alias: "New Device Alert"
  trigger:
    - platform: event
      event_type: device_tracker_new_device
  action:
    - service: notify.admin
      data:
        title: "New Device Detected"
        message: "Device {{ trigger.event.data.entity_id }} detected on network"
    - service: script.quarantine_device
      data:
        device_id: "{{ trigger.event.data.entity_id }}"

- alias: "Security Camera Offline"
  trigger:
    - platform: state
      entity_id: binary_sensor.security_camera_1
      to: 'unavailable'
      for: '00:05:00'
  action:
    - service: notify.security_team
      data:
        title: "Security Alert"
        message: "Security camera 1 has gone offline"
    - service: light.turn_on
      entity_id: light.security_alert_light
      data:
        color_name: red
        brightness: 255

- alias: "Suspicious Network Activity"
  trigger:
    - platform: numeric_state
      entity_id: sensor.network_anomalies
      above: 5
  action:
    - service: notify.admin
      data:
        title: "Network Security Alert"
        message: "{{ states('sensor.network_anomalies') }} network anomalies detected"
    - service: script.enable_enhanced_monitoring
```

## Monitoring and Logging

### Log Configuration

```yaml
# configuration.yaml
logger:
  default: info
  logs:
    homeassistant.core: debug
    homeassistant.components.device_tracker: debug
    homeassistant.components.mqtt: info
    custom_components.security_monitor: debug

recorder:
  db_url: !secret database_url
  purge_keep_days: 30
  include:
    domains:
      - device_tracker
      - binary_sensor
      - sensor
    entity_globs:
      - sensor.security_*
      - binary_sensor.security_*
```

### Health Monitoring

```yaml
# configuration.yaml
system_health:

# Database monitoring
sensor:
  - platform: sql
    db_url: !secret database_url
    queries:
      - name: "Database Size"
        query: "SELECT pg_size_pretty(pg_database_size('homeassistant'));"
        column: "pg_size_pretty"
```

## Backup and Recovery

### Automated Backups

```yaml
# configuration.yaml
backup:
  auto_backup: true
  backup_days: 7
  backup_location: "/backups"
```

### Backup Script

```bash
#!/bin/bash
# backup-homeassistant.sh

BACKUP_DIR="/opt/homeassistant/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="homeassistant_backup_$DATE.tar.gz"

# Create backup
tar -czf "$BACKUP_DIR/$BACKUP_FILE" -C /opt/homeassistant config

# Upload to remote storage
rsync -av "$BACKUP_DIR/$BACKUP_FILE" backup-server:/backups/homeassistant/

# Cleanup old backups (keep last 7 days)
find "$BACKUP_DIR" -name "homeassistant_backup_*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE"
```

## Troubleshooting

### Common Issues

1. **Device Discovery Problems:**
   ```bash
   # Check network connectivity
   ping -c 3 192.168.30.100
   
   # Verify VLAN configuration
   ip route show table all
   
   # Check firewall rules
   iptables -L -n -v
   ```

2. **MQTT Connection Issues:**
   ```bash
   # Test MQTT connectivity
   mosquitto_pub -h localhost -t test/topic -m "test message"
   mosquitto_sub -h localhost -t test/topic
   ```

3. **Performance Issues:**
   ```bash
   # Monitor resource usage
   docker stats homeassistant
   
   # Check database performance
   docker exec -it homeassistant_db psql -U homeassistant -c "SELECT * FROM pg_stat_activity;"
   ```

## Security Best Practices

1. **Regular Updates:**
   - Update Home Assistant monthly
   - Update add-ons and integrations
   - Monitor security advisories

2. **Access Control:**
   - Use strong passwords
   - Enable 2FA for all accounts
   - Regularly review user permissions

3. **Network Security:**
   - Monitor network traffic
   - Review firewall logs
   - Implement intrusion detection

4. **Backup Strategy:**
   - Daily automated backups
   - Test restore procedures
   - Store backups securely offsite

## Additional Resources

- [Home Assistant Security Documentation](https://www.home-assistant.io/docs/configuration/securing/)
- [Home Assistant Network Configuration](https://www.home-assistant.io/docs/configuration/basic/)
- [MQTT Security Best Practices](https://www.hivemq.com/blog/mqtt-security-fundamentals/)