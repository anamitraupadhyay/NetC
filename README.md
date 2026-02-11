# NetC - Network Communication Tools

A collection of network communication tools and implementations, including ONVIF camera simulation, UDP/TCP protocols, and multicast discovery.

## Projects

### ONVIF-SIM
ONVIF camera simulator with WS-Discovery and device management capabilities.

**NEW: Network Interface Binding Support**
- Bind to specific ethernet interfaces or IP addresses
- Control which network the ONVIF camera appears on
- Perfect for multi-network environments

See [ONVIF-SIM/INTERFACE_BINDING.md](ONVIF-SIM/INTERFACE_BINDING.md) for detailed documentation.

Quick start:
```bash
# Run on specific interface
cd ONVIF-SIM/fakecamera/build
./m -i eth0

# Run on specific IP
./m -a 192.168.1.100
```

### Other Components
- **imgsharewithparitycheck**: Image sharing with error correction
- **dynaimgtcp**: Dynamic image transfer over TCP
- **simplemsg**: Simple messaging system
- **kernelimplementationfromscratch**: Kernel implementation experiments
- **onviflibrary**: ONVIF protocol library components

<img width="1102" height="863" alt="image" src="https://github.com/user-attachments/assets/2607310d-7111-43ea-a24a-c842238d270f" />
<img width="960" height="848" alt="image" src="https://github.com/user-attachments/assets/ffbddeae-86c0-441d-a3ba-b1c73a15a953" />
