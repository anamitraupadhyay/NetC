# Network Interface Binding for ONVIF-SIM

## Overview

The ONVIF-SIM fakecamera server and CamDiscoverer tool now support binding to specific network interfaces or IP addresses. This feature allows you to control which network the application appears on when you have multiple ethernet networks with multiple IP addresses assigned.

## Problem Statement

When a system has multiple network interfaces (e.g., eth0, eth1, wlan0) with different IP addresses, the default behavior of binding to `INADDR_ANY` causes the application to listen on ALL network interfaces. This means:

- The ONVIF camera appears on all networks
- Discovery requests from any network are answered
- The application is visible on networks where you may want it hidden

## Solution

The interface binding feature provides two methods to restrict network visibility:

1. **Bind to a specific interface** (e.g., `eth0`, `wlan0`)
2. **Bind to a specific IP address** (e.g., `192.168.1.100`)

When binding is enabled:
- Socket operations use `SO_BINDTODEVICE` to bind to the specified interface
- The bind address uses the specific IP instead of `INADDR_ANY`
- Multicast group membership is limited to the specified interface
- Local IP detection returns the bound interface's IP

## Usage

### ONVIF Fake Camera Server

```bash
# Run on all interfaces (default behavior)
./m

# Bind to specific interface
./m -i eth0
./m --interface eth0

# Bind to specific IP address
./m -a 192.168.1.100
./m --address 192.168.1.100

# Show help
./m -h
./m --help
```

### ONVIF Camera Discoverer

```bash
# Discover on all interfaces (default behavior)
./camdis

# Discover on specific interface
./camdis -i eth0
./camdis --interface eth0

# Discover using specific IP address
./camdis -a 192.168.1.100
./camdis --address 192.168.1.100

# Show help
./camdis -h
./camdis --help
```

## Building

### Fake Camera Server

```bash
cd ONVIF-SIM/fakecamera
mkdir -p build
cd build
cmake ..
make
```

The executable will be at: `ONVIF-SIM/fakecamera/build/m`

### Camera Discoverer

```bash
cd ONVIF-SIM/CamDiscoverer
gcc -o camdis camdis.c -Wall -Wextra
```

The executable will be at: `ONVIF-SIM/CamDiscoverer/camdis`

## Technical Details

### Components Modified

1. **interface_binding.h** (new file)
   - Global state management for interface/IP binding
   - Utility functions for:
     - Setting bind interface/IP
     - Getting bound IP address from interface name
     - Applying `SO_BINDTODEVICE` to sockets
     - Getting bind address (replacing `INADDR_ANY`)
     - Getting multicast interface (replacing `INADDR_ANY`)

2. **main.c** (fakecamera)
   - Added command-line argument parsing with getopt_long
   - Interface binding initialization

3. **discovery_server.h**
   - Modified UDP socket binding to use specific interface/IP
   - Modified multicast group membership to use specific interface
   - Added status messages showing bound interface/IP

4. **auth_server.h**
   - Modified TCP socket binding to use specific interface/IP
   - Added status messages showing bound interface/IP

5. **dis_utils.h**
   - Modified `getlocalip()` to respect interface binding
   - Returns bound IP when interface binding is enabled

6. **camdis.c** (CamDiscoverer)
   - Added command-line argument parsing
   - Applied interface binding to discovery client

### Key Changes Summary

#### Before (binds to ALL interfaces):
```c
addr.sin_addr.s_addr = INADDR_ANY;
mreq.imr_interface.s_addr = INADDR_ANY;
```

#### After (binds to specific interface/IP):
```c
// Get specific IP or use INADDR_ANY if not configured
get_bind_address(&addr.sin_addr);

// Apply SO_BINDTODEVICE if interface name specified
apply_interface_binding(sockfd);

// Use specific interface for multicast
get_multicast_interface(&mreq.imr_interface);
```

## Use Cases

### Scenario 1: Multiple Corporate Networks

You have:
- `eth0`: 192.168.1.100 (Corporate network)
- `eth1`: 10.0.0.50 (Management network)

You want the ONVIF camera to appear only on the corporate network:

```bash
./m -i eth0
# or
./m -a 192.168.1.100
```

Result: The camera is discoverable on 192.168.1.x network but invisible on 10.0.0.x network.

### Scenario 2: Segregated Testing Environment

You have:
- `eth0`: Connected to production network
- `eth1`: Connected to test network

Run the fake camera only on the test network:

```bash
./m -i eth1
```

### Scenario 3: Multi-homed Server

Your server has multiple IPs on the same interface. You want to bind to a specific IP:

```bash
./m -a 192.168.10.100
```

## Verification

To verify the binding is working:

1. **Check server startup messages:**
   ```
   [Interface Binding] Set to interface: eth0
   Bound to port 3702 on 192.168.1.100
   TCP server bound to port 7000 on 192.168.1.100
   ```

2. **Use netstat to verify socket binding:**
   ```bash
   netstat -tulpn | grep <port>
   ```
   
   With interface binding:
   ```
   udp  0  0  192.168.1.100:3702  0.0.0.0:*
   tcp  0  0  192.168.1.100:7000  0.0.0.0:*  LISTEN
   ```
   
   Without interface binding (default):
   ```
   udp  0  0  0.0.0.0:3702        0.0.0.0:*
   tcp  0  0  0.0.0.0:7000        0.0.0.0:*  LISTEN
   ```

3. **Try discovery from different networks:**
   - From the bound network: Discovery should succeed
   - From other networks: Discovery should fail/timeout

## Limitations

1. **Requires root/CAP_NET_RAW**: The `SO_BINDTODEVICE` socket option requires elevated privileges on Linux. If you see permission errors, run with sudo:
   ```bash
   sudo ./m -i eth0
   ```

2. **Interface must exist**: The specified interface must exist on the system. Use `ip addr` or `ifconfig` to list available interfaces.

3. **IP must be assigned**: When using `-a`, the IP address must be assigned to one of the system's interfaces.

## Backward Compatibility

The changes are **fully backward compatible**:
- Without `-i` or `-a`, the programs behave exactly as before (bind to all interfaces)
- Existing scripts and deployments continue to work unchanged
- Only when you explicitly specify an interface/IP does the binding take effect

## Configuration File Support

The `config.xml` file already contains an `<interface_token>` field:
```xml
<interface_token>eth0</interface_token>
```

However, this is currently only used for informational purposes in ONVIF GetNetworkInterfaces responses. The command-line arguments (`-i` / `-a`) provide runtime control over binding, which is more flexible than config file settings.

## Troubleshooting

### "Operation not permitted" when binding to interface
- **Cause**: `SO_BINDTODEVICE` requires root privileges
- **Solution**: Run with sudo: `sudo ./m -i eth0`

### "bind() failed: Cannot assign requested address"
- **Cause**: The specified IP address is not assigned to any interface
- **Solution**: Check with `ip addr` and use a valid IP

### "Could not find IP for interface: eth0"
- **Cause**: The specified interface doesn't exist or has no IPv4 address
- **Solution**: Check with `ip addr` and ensure interface exists and has an IP

### Discovery not working
- **Cause**: Multicast routing or firewall issues
- **Solution**: Ensure multicast is enabled on the interface and firewall allows UDP port 3702

## Future Enhancements

Potential improvements for future versions:
- Support binding from config.xml in addition to command-line
- IPv6 support
- Multiple interface binding
- Interface hotplug support (handle interface up/down events)
- Automatic interface selection based on network topology

## References

- [ONVIF Device Management Specification](https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf)
- [WS-Discovery Specification](http://docs.oasis-open.org/ws-dd/discovery/1.1/wsdd-discovery-1.1-spec.html)
- [Linux socket(7) man page](https://man7.org/linux/man-pages/man7/socket.7.html)
- [IP multicast programming guide](https://tldp.org/HOWTO/Multicast-HOWTO.html)
