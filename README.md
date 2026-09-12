# Holynet VPN

<img src="https://avatars.githubusercontent.com/u/202399815?s=400" align="right" alt="Holynet logo" height="178">

Holynet VPN is a high-performance VPN protocol built with Rust, designed for fast and secure connections over UDP.

* **UDP-based** for low-latency and high-throughput communication;
* Can be used as a **library** for integrating VPN functionality into custom applications or services;
* Supports two cryptographic algorithms based on the **Noise IK+PSK2 protocol**: clients can choose between **AES** or **ChaCha** encryption depending on the device, such as mobile devices;
* Cross-platform support for **Linux**, **macOS**, (and Windows planned);
* **Optimized for performance** with minimal impact on speed and overhead.

> [!WARNING]  
> Not ready for prod

## Usage
```
Holynet VPN command-line interface.

Usage: holynet [OPTIONS] <COMMAND>

Commands:
  connect  Connect to a VPN server
  server   Server management
  help     Print this message or the help of the given subcommand(s)

Options:
  -d, --debug    Enable debug logging
  -h, --help     Print help
  -V, --version  Print version
```

## Protocol

The wire protocol (frame types, handshake and device enrollment, the control
channel, node-to-node gossip, liveness, transparent relay, and the routing
overlay) is documented in [docs/protocol/README.md](docs/protocol/README.md).

At a glance: UDP transport, Noise IKpsk2 sessions (AES or ChaCha), a control
channel piggybacked on the data frames (address lease, node list, routing edges),
node-to-node registry gossip, liveness probes, and an untrusted transparent relay
for arbitrary-depth multi-hop.

## License
Licensed under the [Apache License 2.0](LICENSE)  
Copyright © 2024 Nikita Boyarshinov (JKearnsl)

**Attribution Requirements:**  
All distributions must retain:
- Original copyright notices
- License text
- NOTICE file contents
