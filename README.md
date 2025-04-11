# Holynet VPN

<img src="docs/icons/icon.svg" align="right" alt="Holynet logo" width="120" height="178">

Holynet VPN is a high-performance VPN protocol built with Rust, designed for fast and secure connections over UDP.

* **UDP-based** for low-latency and high-throughput communication;
* Can be used as a **library** for integrating VPN functionality into custom applications or services;
* Supports two cryptographic algorithms based on the **Noise IK+PSK2 protocol**: clients can choose between **AES** or **ChaCha** encryption depending on the device, such as mobile devices;
* Cross-platform support for **Linux**, **macOS**, (and Windows planned);
* **Optimized for performance** with minimal impact on speed and overhead.

## Usage
```
Usage: server [OPTIONS] <COMMAND>

Commands:
  start    Start VPN server
  users    Users management
  monitor  Monitor VPN server
  logs     Shows VPN server logs
  help     Print this message or the help of the given subcommand(s)

Options:
  -d, --debug          Turn debugging information on
  -c, --config <FILE>  
  -h, --help           Print help
  -V, --version        Print version
```
```
Usage: client-cli [OPTIONS] <COMMAND>

Commands:
  connect  connect to a server
  help     Print this message or the help of the given subcommand(s)

Options:
  -d, --debug    Turn debugging information on
  -h, --help     Print help
  -V, --version  Print version
```

## Protocol schema
