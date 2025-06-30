# VLAN Configuration Guide

This guide covers the implementation of VLAN segmentation for secure smart home infrastructure.

## Table of Contents

1. [VLAN Overview](#vlan-overview)
2. [Network Design](#network-design)
3. [Switch Configuration](#switch-configuration)
4. [Firewall Rules](#firewall-rules)
5. [Device Assignment](#device-assignment)
6. [Troubleshooting](#troubleshooting)

## VLAN Overview

### VLAN Segmentation Strategy

Our smart home network is segmented into multiple VLANs to isolate different types of devices and limit potential attack vectors:

```
VLAN 10 - Management (192.168.10.0/24)
├── Network equipment (switches, APs, router)
├── Home Assistant server
├── Monitoring systems (Grafana, InfluxDB)
└── Network management tools

VLAN 20 - Trusted Devices (192.168.20.0/24)
├── Personal computers and laptops
├── Smartphones and tablets
├── Work devices
└── Trusted servers

VLAN 30 - IoT Devices (192.168.30.0/24)
├── Smart lights and switches
├── Sensors and thermostats
├── Smart plugs
└── Voice assistants (isolated)

VLAN 40 - Security Devices (192.168.40.0/24)
├── Security cameras
├── Smart door locks
├── Motion sensors
└── Alarm systems

VLAN 50 - Guest Network (192.168.50.0/24)
├── Guest devices
├── Temporary access
└── Untrusted devices

VLAN 60 - Quarantine (192.168.60.0/24)
├── New/unknown devices
├── Compromised devices
└── Devices under investigation
```

## Network Design

### Core Principles

1. **Default Deny**: All inter-VLAN communication is blocked by default
2. **Least Privilege**: Devices only have access to required services
3. **Monitoring**: All traffic is logged and monitored
4. **Isolation**: Critical devices are isolated from internet access

### Traffic Flow Rules

#### Management VLAN (10)
- **Inbound**: SSH, HTTPS, SNMP from trusted devices
- **Outbound**: Internet access for updates, NTP
- **Inter-VLAN**: Access to all VLANs for management

#### Trusted Devices VLAN (20)
- **Inbound**: Standard services (HTTP, HTTPS, SSH)
- **Outbound**: Full internet access
- **Inter-VLAN**: Access to IoT and Security VLANs

#### IoT Devices VLAN (30)
- **Inbound**: Home Assistant communication
- **Outbound**: Limited internet (firmware updates only)
- **Inter-VLAN**: No direct access to other VLANs

#### Security Devices VLAN (40)
- **Inbound**: Home Assistant and monitoring systems
- **Outbound**: No internet access (local only)
- **Inter-VLAN**: No access to other VLANs

#### Guest Network VLAN (50)
- **Inbound**: Basic web services
- **Outbound**: Internet access only
- **Inter-VLAN**: No access to internal VLANs

#### Quarantine VLAN (60)
- **Inbound**: Management access only
- **Outbound**: No internet access
- **Inter-VLAN**: No access to other VLANs

## Switch Configuration

### Cisco/HP Switch Example

```
# Create VLANs
vlan 10
 name Management
vlan 20
 name Trusted-Devices
vlan 30
 name IoT-Devices
vlan 40
 name Security-Devices
vlan 50
 name Guest-Network
vlan 60
 name Quarantine

# Configure trunk ports (to router/firewall)
interface GigabitEthernet0/1
 description Trunk to Router
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,40,50,60
 switchport trunk native vlan 10

# Configure access ports for IoT devices
interface range GigabitEthernet0/2-12
 description IoT Devices
 switchport mode access
 switchport access vlan 30
 spanning-tree portfast
 spanning-tree bpduguard enable

# Configure access ports for security devices
interface range GigabitEthernet0/13-18
 description Security Devices
 switchport mode access
 switchport access vlan 40
 spanning-tree portfast
 spanning-tree bpduguard enable

# Configure management interface
interface vlan 10
 ip address 192.168.10.2 255.255.255.0
 no shutdown
```

### Unifi Switch Configuration

```json
{
  "vlans": [
    {
      "id": 10,
      "name": "Management",
      "subnet": "192.168.10.0/24",
      "gateway": "192.168.10.1"
    },
    {
      "id": 20,
      "name": "Trusted-Devices",
      "subnet": "192.168.20.0/24",
      "gateway": "192.168.20.1"
    },
    {
      "id": 30,
      "name": "IoT-Devices",
      "subnet": "192.168.30.0/24",
      "gateway": "192.168.30.1"
    },
    {
      "id": 40,
      "name": "Security-Devices",
      "subnet": "192.168.40.0/24",
      "gateway": "192.168.40.1"
    },
    {
      "id": 50,
      "name": "Guest-Network",
      "subnet": "192.168.50.0/24",
      "gateway": "192.168.50.1"
    },
    {
      "id": 60,
      "name": "Quarantine",
      "subnet": "192.168.60.0/24",
      "gateway": "192.168.60.1"
    }
  ],
  "port_profiles": [
    {
      "name": "IoT-Device",
      "native_vlan": 30,
      "tagged_vlans": []
    },
    {
      "name": "Security-Device",
      "native_vlan": 40,
      "tagged_vlans": []
    },
    {
      "name": "Trusted-Device",
      "native_vlan": 20,
      "tagged_vlans": []
    }
  ]
}
```

## Firewall Rules

### pfSense Configuration

#### Interface Assignment
```
WAN: em0 (Internet)
LAN_MGMT: em1.10 (Management VLAN)
LAN_TRUSTED: em1.20 (Trusted Devices VLAN)
LAN_IOT: em1.30 (IoT Devices VLAN)
LAN_SECURITY: em1.40 (Security Devices VLAN)
LAN_GUEST: em1.50 (Guest Network VLAN)
LAN_QUARANTINE: em1.60 (Quarantine VLAN)
```

#### Firewall Rules

**Management VLAN Rules:**
```
# Allow management access to all VLANs
Pass | IPv4 | LAN_MGMT net | * | LAN_TRUSTED net | * | *
Pass | IPv4 | LAN_MGMT net | * | LAN_IOT net | * | *
Pass | IPv4 | LAN_MGMT net | * | LAN_SECURITY net | * | *

# Allow internet access for updates
Pass | IPv4 | LAN_MGMT net | * | * | 80,443 | *

# Allow NTP
Pass | IPv4 | LAN_MGMT net | * | * | 123 | *
```

**Trusted Devices Rules:**
```
# Allow access to IoT and Security VLANs
Pass | IPv4 | LAN_TRUSTED net | * | LAN_IOT net | * | *
Pass | IPv4 | LAN_TRUSTED net | * | LAN_SECURITY net | * | *

# Allow internet access
Pass | IPv4 | LAN_TRUSTED net | * | * | * | *

# Block access to management VLAN
Block | IPv4 | LAN_TRUSTED net | * | LAN_MGMT net | * | *
```

**IoT Devices Rules:**
```
# Allow Home Assistant communication
Pass | IPv4 | LAN_IOT net | * | 192.168.10.100 | 8123 | *

# Allow limited internet for updates
Pass | IPv4 | LAN_IOT net | * | * | 80,443 | *

# Block all other inter-VLAN communication
Block | IPv4 | LAN_IOT net | * | RFC1918 | * | *
```

**Security Devices Rules:**
```
# Allow Home Assistant communication
Pass | IPv4 | LAN_SECURITY net | * | 192.168.10.100 | 8123 | *

# Allow monitoring systems
Pass | IPv4 | LAN_SECURITY net | * | 192.168.10.0/24 | 3000,8086 | *

# Block internet access
Block | IPv4 | LAN_SECURITY net | * | !RFC1918 | * | *

# Block other inter-VLAN communication
Block | IPv4 | LAN_SECURITY net | * | RFC1918 | * | *
```

**Guest Network Rules:**
```
# Allow internet access only
Pass | IPv4 | LAN_GUEST net | * | !RFC1918 | * | *

# Block all RFC1918 (private) networks
Block | IPv4 | LAN_GUEST net | * | RFC1918 | * | *
```

**Quarantine Rules:**
```
# Block all traffic except management
Pass | IPv4 | LAN_MGMT net | * | LAN_QUARANTINE net | 22 | *
Block | IPv4 | LAN_QUARANTINE net | * | * | * | *
```

## Device Assignment

### Automatic VLAN Assignment

#### DHCP Reservations by MAC Address
```
# IoT Devices
192.168.30.10 - Philips Hue Bridge (00:17:88:xx:xx:xx)
192.168.30.11 - Smart Thermostat (b8:27:eb:xx:xx:xx)
192.168.30.12 - Smart Switch 1 (2c:3a:e8:xx:xx:xx)

# Security Devices
192.168.40.10 - Security Camera 1 (00:12:34:xx:xx:xx)
192.168.40.11 - Smart Door Lock (aa:bb:cc:xx:xx:xx)
192.168.40.12 - Motion Sensor Hub (11:22:33:xx:xx:xx)
```

#### 802.1X Authentication (Advanced)
```
# RADIUS configuration for dynamic VLAN assignment
# Based on device certificates or MAC address database
```

### Manual Device Classification

#### Device Discovery Script
```bash
#!/bin/bash
# Scan for new devices and suggest VLAN assignment

nmap -sn 192.168.0.0/16 | grep -E "Nmap scan report|MAC Address" | \
while read line; do
    if [[ $line == *"Nmap scan report"* ]]; then
        ip=$(echo $line | awk '{print $5}')
    elif [[ $line == *"MAC Address"* ]]; then
        mac=$(echo $line | awk '{print $3}')
        vendor=$(echo $line | cut -d'(' -f2 | cut -d')' -f1)
        echo "Device: $ip - MAC: $mac - Vendor: $vendor"
        
        # Suggest VLAN based on vendor
        case $vendor in
            *Philips*|*LIFX*|*TP-Link*) echo "  Suggested VLAN: 30 (IoT)" ;;
            *Hikvision*|*Dahua*|*Axis*) echo "  Suggested VLAN: 40 (Security)" ;;
            *Apple*|*Samsung*|*Google*) echo "  Suggested VLAN: 20 (Trusted)" ;;
            *) echo "  Suggested VLAN: 60 (Quarantine)" ;;
        esac
    fi
done
```

## Monitoring and Maintenance

### VLAN Health Monitoring

```bash
#!/bin/bash
# Monitor VLAN health and connectivity

for vlan in 10 20 30 40 50 60; do
    gateway="192.168.$vlan.1"
    if ping -c 1 $gateway &>/dev/null; then
        echo "VLAN $vlan: OK"
    else
        echo "VLAN $vlan: FAILED"
        # Send alert
    fi
done
```

### Traffic Analysis

```bash
# Monitor inter-VLAN traffic
tcpdump -i any vlan and host 192.168.30.0/24

# Check for unauthorized communication
netstat -rn | grep -E "192.168.(10|20|30|40|50|60)"
```

## Troubleshooting

### Common Issues

1. **Device can't reach internet**
   - Check VLAN assignment
   - Verify firewall rules
   - Test DNS resolution

2. **Inter-VLAN communication blocked**
   - Review firewall rules
   - Check routing table
   - Verify VLAN configuration

3. **Device in wrong VLAN**
   - Check switch port configuration
   - Verify DHCP reservations
   - Update device assignment

### Diagnostic Commands

```bash
# Check VLAN configuration
show vlan brief

# Verify trunk ports
show interfaces trunk

# Check MAC address table
show mac address-table

# Test connectivity
ping vrf VLAN30 192.168.30.1
```

### Log Analysis

```bash
# Check firewall logs
tail -f /var/log/filter.log | grep VLAN

# Monitor DHCP assignments
tail -f /var/log/dhcpd.log

# Check switch logs
show logging | include VLAN
```

## Security Best Practices

1. **Regular Audits**: Review device assignments monthly
2. **Monitoring**: Implement continuous network monitoring
3. **Updates**: Keep firmware updated on all network equipment
4. **Documentation**: Maintain accurate network documentation
5. **Testing**: Regularly test firewall rules and connectivity
6. **Backup**: Backup all network configurations
7. **Change Management**: Document all network changes