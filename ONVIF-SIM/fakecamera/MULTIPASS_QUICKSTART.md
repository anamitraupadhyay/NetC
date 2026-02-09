# Multipass Quick Start for DNS Testing

This is a quick reference for setting up and using Multipass to safely test the DNS configuration code.

## Installation

```bash
# Ubuntu/WSL
sudo snap install multipass

# macOS
brew install multipass

# Windows - Download from https://multipass.run/
```

## Basic VM Management

```bash
# Create a VM
multipass launch --name dns-test --cpus 1 --memory 1G --disk 5G ubuntu:22.04

# List VMs
multipass list

# Get shell access
multipass shell dns-test

# Check VM info
multipass info dns-test

# Stop VM
multipass stop dns-test

# Start VM
multipass start dns-test

# Delete VM
multipass delete dns-test
multipass purge  # Actually remove deleted VMs
```

## File Transfer

```bash
# Copy file TO VM
multipass transfer /local/path/file.txt dns-test:/home/ubuntu/

# Copy directory TO VM
multipass transfer -r /local/directory dns-test:/home/ubuntu/

# Copy file FROM VM
multipass transfer dns-test:/home/ubuntu/file.txt ./

# Mount local directory in VM
multipass mount /local/path dns-test:/mount/point
```

## Complete Testing Workflow

### 1. Create and Setup VM

```bash
# Create VM
multipass launch --name dns-test --cpus 1 --memory 1G ubuntu:22.04

# Transfer entire fakecamera directory
cd /path/to/NetC
multipass transfer -r ONVIF-SIM/fakecamera dns-test:/home/ubuntu/

# Get into VM
multipass shell dns-test
```

### 2. Setup Multiple IPs (Inside VM)

```bash
# Show current network interface
ip addr show

# Add secondary IPs (example with interface enp0s2)
sudo ip addr add 192.168.64.10/24 dev enp0s2
sudo ip addr add 192.168.64.11/24 dev enp0s2

# Verify
ip addr show enp0s2
hostname -I
```

### 3. Install Dependencies and Run Tests (Inside VM)

```bash
cd /home/ubuntu/fakecamera

# Make test script executable
chmod +x test_dns_safe.sh

# Run the safe test script
./test_dns_safe.sh

# Or compile and test manually
gcc -o test_applydns test_applydns.c
sudo ./test_applydns
```

### 4. Review Results

```bash
# Check resolv.conf
cat /etc/resolv.conf

# Test DNS resolution
nslookup google.com
ping -c 3 google.com

# Check if fallback was triggered
dmesg | tail -20
```

### 5. Test Different Scenarios

**Scenario A: Normal DNS with addr in config.xml**
```bash
cat > config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<config>
    <searchdomain>example.com</searchdomain>
    <addr>8.8.8.8</addr>
</config>
EOF

sudo ./test_applydns
cat /etc/resolv.conf
# Should show: nameserver 8.8.8.8
```

**Scenario B: Fallback without addr**
```bash
cat > config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<config>
    <searchdomain>example.com</searchdomain>
</config>
EOF

sudo ./test_applydns
cat /etc/resolv.conf
# Should show: nameserver [first-ip-from-hostname-i]
```

**Scenario C: Multiple IPs (tests fallback IP selection)**
```bash
# Add more IPs
sudo ip addr add 10.0.0.1/24 dev enp0s2
sudo ip addr add 10.0.0.2/24 dev enp0s2

# Check all IPs
hostname -I

# Run fallback test
cat > config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<config>
    <searchdomain>example.com</searchdomain>
</config>
EOF

sudo ./test_applydns
cat /etc/resolv.conf
# Should show the first IP from gethostbyname()
```

### 6. Cleanup and Exit

```bash
# Exit VM
exit

# Stop VM
multipass stop dns-test

# Delete when done
multipass delete dns-test
multipass purge
```

## Advanced: Setting Up Two VMs for Network Testing

```bash
# Create two VMs
multipass launch --name dns-primary ubuntu:22.04
multipass launch --name dns-secondary ubuntu:22.04

# In primary VM
multipass shell dns-primary
sudo ip addr add 192.168.100.10/24 dev enp0s2

# In secondary VM  
multipass shell dns-secondary
sudo ip addr add 192.168.100.20/24 dev enp0s2

# Test connectivity between VMs
# From primary:
ping 192.168.100.20

# From secondary:
ping 192.168.100.10
```

## Troubleshooting

### Problem: Can't connect to VM
```bash
multipass list  # Check if VM is running
multipass start dns-test  # Start if stopped
multipass restart dns-test  # Restart if needed
```

### Problem: Network not working in VM
```bash
# Inside VM
sudo systemctl restart systemd-networkd
sudo systemctl restart systemd-resolved
```

### Problem: Can't add secondary IPs
```bash
# Check interface name
ip link show

# Use correct interface name (might be eth0, enp0s2, etc.)
sudo ip addr add 192.168.64.10/24 dev [correct-interface-name]
```

### Problem: Permission denied on /etc/resolv.conf
```bash
# Check if systemd-resolved is managing it
ls -la /etc/resolv.conf

# If it's a symlink to /run/systemd/resolve/stub-resolv.conf
# Disable systemd-resolved temporarily
sudo systemctl stop systemd-resolved
sudo rm /etc/resolv.conf
sudo touch /etc/resolv.conf

# Or modify code to write to /etc/resolv.conf.manual instead
```

### Problem: VM uses too much disk space
```bash
# Clean up inside VM
sudo apt-get clean
sudo apt-get autoremove

# Or create VM with more disk
multipass launch --name dns-test --disk 10G
```

## Why Multipass is Better Than Docker for This Test

1. ✅ **Full systemd support** - better mimics real Ubuntu server
2. ✅ **Real network stack** - can add multiple IPs easily
3. ✅ **No privileged mode needed** - more secure
4. ✅ **True /etc/resolv.conf behavior** - not bind-mounted
5. ✅ **Can test system-level networking** - full OS isolation
6. ✅ **Easy to snapshot and restore** - quick rollback

## Summary

```bash
# Quick test workflow:
multipass launch --name dns-test ubuntu:22.04
multipass transfer -r ONVIF-SIM/fakecamera dns-test:/home/ubuntu/
multipass shell dns-test
cd /home/ubuntu/fakecamera
chmod +x test_dns_safe.sh
./test_dns_safe.sh
exit
multipass delete dns-test && multipass purge
```

**Total time: ~5 minutes for complete isolated test environment!**
