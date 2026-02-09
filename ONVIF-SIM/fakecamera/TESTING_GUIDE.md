# Testing Guide for DNS Configuration Code

This guide explains how to safely test the DNS configuration functionality without risking damage to your main OS (WSL or Ubuntu).

## Table of Contents
1. [Safety Concerns](#safety-concerns)
2. [Testing with Multipass (Recommended)](#testing-with-multipass-recommended)
3. [Testing with Docker (Alternative)](#testing-with-docker-alternative)
4. [Testing with Network Namespaces (Linux Only)](#testing-with-network-namespaces-linux-only)
5. [Testing the Fallback Mechanism](#testing-the-fallback-mechanism)

---

## Safety Concerns

The `applydnstoservice()` function modifies `/etc/resolv.conf`, which is critical for DNS resolution. Incorrect modifications can:
- Break internet connectivity
- Prevent domain name resolution
- Require manual intervention to restore

**DO NOT test directly on your main OS without isolation.**

---

## Testing with Multipass (Recommended)

Multipass is ideal for this testing as it creates isolated Ubuntu VMs.

### Step 1: Install Multipass

```bash
# On Ubuntu/WSL
sudo snap install multipass

# On macOS
brew install multipass

# On Windows
# Download from https://multipass.run/
```

### Step 2: Create Test VMs

```bash
# Create a VM with specific network configuration
multipass launch --name dns-test-1 --cpus 1 --memory 1G --disk 5G

# Create a second VM for multi-network testing
multipass launch --name dns-test-2 --cpus 1 --memory 1G --disk 5G
```

### Step 3: Set Up Multiple IPs (for fallback testing)

```bash
# Get shell in first VM
multipass shell dns-test-1

# Inside VM: Add a secondary IP to the interface
sudo ip addr add 192.168.100.10/24 dev enp0s2
sudo ip addr add 192.168.100.11/24 dev enp0s2

# Verify multiple IPs
ip addr show
```

### Step 4: Transfer and Build Code

```bash
# On host: Transfer the code
multipass transfer /path/to/NetC/ONVIF-SIM/fakecamera dns-test-1:/home/ubuntu/

# In VM: Build the code
multipass shell dns-test-1
cd /home/ubuntu/fakecamera
gcc -o test_dns main.c -pthread
```

### Step 5: Test DNS Configuration

```bash
# Backup original resolv.conf
sudo cp /etc/resolv.conf /etc/resolv.conf.backup

# Run the test
sudo ./test_dns

# Check the result
cat /etc/resolv.conf

# Restore if needed
sudo cp /etc/resolv.conf.backup /etc/resolv.conf
```

### Step 6: Clean Up

```bash
# Exit VM
exit

# Delete VMs when done
multipass delete dns-test-1 dns-test-2
multipass purge
```

---

## Testing with Docker (Alternative)

Docker provides good isolation but requires privileged mode for network modifications.

### Step 1: Create Dockerfile

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    make \
    iproute2 \
    iputils-ping \
    dnsutils \
    net-tools

WORKDIR /app
COPY ONVIF-SIM/fakecamera /app/

RUN gcc -o test_dns main.c -pthread

CMD ["/bin/bash"]
```

### Step 2: Build and Run

```bash
# Build image
docker build -t dns-test .

# Run with privileged mode (needed to modify /etc/resolv.conf)
docker run -it --privileged --cap-add=NET_ADMIN dns-test

# Inside container: Test the code
./test_dns
cat /etc/resolv.conf

# Container is isolated - no risk to host
```

### Step 3: Multi-IP Testing in Docker

```bash
# Inside container: Add multiple IPs
ip addr add 172.17.0.10/16 dev eth0
ip addr add 172.17.0.11/16 dev eth0

# Verify
ip addr show eth0

# Test fallback
./test_dns
```

---

## Testing with Network Namespaces (Linux Only)

Most lightweight option, but Linux-specific.

### Step 1: Create Network Namespace

```bash
# Create namespace
sudo ip netns add dns-test

# Set up virtual interface pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns dns-test

# Configure interfaces
sudo ip addr add 10.0.0.1/24 dev veth0
sudo ip link set veth0 up

sudo ip netns exec dns-test ip addr add 10.0.0.2/24 dev veth1
sudo ip netns exec dns-test ip link set veth1 up
sudo ip netns exec dns-test ip link set lo up
```

### Step 2: Add Multiple IPs in Namespace

```bash
# Add secondary IPs for fallback testing
sudo ip netns exec dns-test ip addr add 10.0.0.3/24 dev veth1
sudo ip netns exec dns-test ip addr add 10.0.0.4/24 dev veth1
```

### Step 3: Test in Namespace

```bash
# Copy your binary to a shared location
sudo cp /path/to/test_dns /tmp/

# Run in namespace
sudo ip netns exec dns-test /tmp/test_dns

# Check resolv.conf in namespace
sudo ip netns exec dns-test cat /etc/resolv.conf
```

### Step 4: Clean Up

```bash
sudo ip netns delete dns-test
sudo ip link delete veth0
```

---

## Testing the Fallback Mechanism

The fallback mechanism (lines 453-499) activates when no DNS address is found in config.xml.

### Test Case 1: Normal Operation (addr found in config.xml)

```bash
# Edit config.xml to have an addr
cat > config.xml << EOF
<?xml version="1.0" encoding="utf-8"?>
<config>
    <searchdomain>example.com</searchdomain>
    <addr>8.8.8.8</addr>
</config>
EOF

# Run test
sudo ./test_dns

# Expected: /etc/resolv.conf should have:
# search example.com
# nameserver 8.8.8.8
```

### Test Case 2: Fallback (no addr in config.xml)

```bash
# Edit config.xml to remove addr
cat > config.xml << EOF
<?xml version="1.0" encoding="utf-8"?>
<config>
    <searchdomain>example.com</searchdomain>
</config>
EOF

# Run test
sudo ./test_dns

# Expected: /etc/resolv.conf should use first IP from gethostbyname()
# The console will show: "no dns address found in config.xml"
```

### Test Case 3: Multi-IP Fallback

```bash
# Add multiple IPs to your test interface
sudo ip addr add 192.168.1.10/24 dev eth0
sudo ip addr add 192.168.1.11/24 dev eth0

# Remove addr from config.xml (same as Test Case 2)

# Run test
sudo ./test_dns

# Expected: Uses host_entry->h_addr_list[0] (first IP)
# Check with: hostname -I
```

---

## Verification Script

Create this script to verify DNS changes safely:

```bash
#!/bin/bash
# verify_dns_test.sh

echo "=== DNS Test Verification ==="

# Backup
if [ ! -f /etc/resolv.conf.test_backup ]; then
    sudo cp /etc/resolv.conf /etc/resolv.conf.test_backup
    echo "✓ Backup created"
fi

# Show current state
echo -e "\n=== Current /etc/resolv.conf ==="
cat /etc/resolv.conf

# Test DNS resolution
echo -e "\n=== Testing DNS Resolution ==="
if nslookup google.com > /dev/null 2>&1; then
    echo "✓ DNS resolution working"
else
    echo "✗ DNS resolution FAILED"
    echo "Restoring backup..."
    sudo cp /etc/resolv.conf.test_backup /etc/resolv.conf
fi

# Show IPs
echo -e "\n=== Current IP Addresses ==="
hostname -I

echo -e "\n=== Test Complete ==="
```

---

## Recommended Testing Workflow

1. **Use Multipass** for most realistic testing (full VM isolation)
2. **Start with Test Case 1** (normal operation with addr in config.xml)
3. **Then Test Case 2** (fallback without addr)
4. **Finally Test Case 3** (multi-IP fallback)
5. **Always backup `/etc/resolv.conf`** before testing
6. **Verify DNS resolution** after each test with `nslookup` or `ping`

---

## Troubleshooting

### Problem: Permission denied writing to /etc/resolv.conf
**Solution**: Run with `sudo` or in a VM/container where you have root access

### Problem: Can't add multiple IPs
**Solution**: Ensure you have CAP_NET_ADMIN capability (use `--privileged` in Docker or `sudo` on host)

### Problem: Fallback uses wrong IP
**Solution**: Check `hostname -I` to see all IPs. The fallback uses `gethostbyname()` which returns the first IP in the list.

### Problem: DNS resolution breaks after test
**Solution**: Restore from backup: `sudo cp /etc/resolv.conf.backup /etc/resolv.conf`

---

## Security Notes

- Never test on production systems
- Always have a backup of `/etc/resolv.conf`
- Use isolated environments (Multipass, Docker, or netns)
- The code writes to `/etc/resolv.conf` which requires root privileges
- In WSL, `/etc/resolv.conf` may be auto-generated - check `/etc/wsl.conf`

---

## Summary

**Best Practice**: Use Multipass VMs for safe, isolated testing with full network stack simulation. This allows you to test both normal operation and fallback scenarios without any risk to your main OS.
