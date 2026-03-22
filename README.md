# synapse

A fast, barebones Rust port scanner. Supports multiple raw TCP scan techniques, UDP scanning, ICMP + TCP SYN host discovery, PTR DNS resolution, and service name lookup.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/meghp89/synapse/main/install.sh | bash
```

Downloads a pre-built binary for your platform. Falls back to building from source (requires Rust) if no binary is available. The `nmap-services` data file is installed to `/usr/local/share/synapse/`.

---

## Features

- **SYN scan** — raw TCP SYN, never completes the handshake
- **FIN / NULL / XMAS scans** — RFC-compliant evasion techniques; report `open|filtered` vs `closed`
- **ACK scan** — maps firewall rules rather than port state
- **UDP scan** — async UDP probe with ICMP port-unreachable detection
- **Connect scan** — full TCP connect, async with configurable concurrency
- **ICMP host discovery** — ping sweep before scanning, skips dead hosts
- **TCP SYN discovery** — fallback discovery for hosts that block ICMP
- **PTR DNS resolution** — reverse-resolves IPs to hostnames
- **Service lookup** — maps open ports to service names from `nmap-services`
- **Flexible targeting** — single IP, CIDR blocks, octet ranges (e.g. `10.0.0.1-50`), or hostnames
- **Sensitive DNS exclusions** — public DNS infrastructure always excluded from scans

---

## Requirements

- **Root / CAP_NET_RAW** required for all raw socket scan types (SYN, FIN, NULL, XMAS, ACK) and ICMP discovery

---

## Build from source

```bash
cargo build --release
```

---

## Usage

```
sudo synapse [OPTIONS] --target <TARGET>
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | *(required)* | IP, hostname, CIDR, or octet range |
| `--ports` | `-p` | Top 20 common ports | Comma-separated or range (e.g. `80,443` or `1-1024`) |
| `--scan-type` | `-s` | `connect` | `connect`, `syn`, `fin`, `null`, `xmas`, `ack`, `udp` |
| `--threads` | | `1000` | Max concurrent tasks |
| `--timeout` | | `500` | Timeout per port in milliseconds |
| `--output` | `-o` | `false` | Save results to `results/` |
| `--bench` | | `false` | Print performance analysis |

### Scan types

| Type | Flags sent | Requires root | Use case |
|------|-----------|---------------|----------|
| `connect` | — | No | Default; full TCP handshake |
| `syn` | SYN | Yes | Half-open; faster and less logged |
| `fin` | FIN | Yes | Evasion; bypasses some firewalls |
| `null` | *(none)* | Yes | Evasion; same semantics as FIN |
| `xmas` | FIN+PSH+URG | Yes | Evasion; same semantics as FIN |
| `ack` | ACK | Yes | Firewall mapping, not port state |
| `udp` | — (UDP) | No | UDP service discovery |

### Examples

```bash
# TCP connect scan on default ports
sudo synapse -t 192.168.1.1

# SYN scan a /24 subnet on ports 22, 80, 443
sudo synapse -t 10.0.0.0/24 -p 22,80,443 -s syn

# FIN scan to evade basic stateless firewalls
sudo synapse -t 10.0.0.1 -p 1-1024 -s fin

# ACK scan to map firewall rules
sudo synapse -t 10.0.0.1 -p 22,80,443 -s ack

# UDP scan common ports
sudo synapse -t 10.0.0.1 -p 53,67,123,161,500 -s udp

# Octet range scan with output saved
sudo synapse -t 192.168.1.1-50 -p 1-1024 -o
```

---

## Output

```
Starting synapse (Syn scan) against 1 host(s), 20 ports | timeout: 500ms | threads: 1000
────────────────────────────────────────────────────────────

Host Discovery (1.23s)
  [UP  ]  router.local (192.168.1.1)

1 live host(s) to scan
────────────────────────────────────────────────────────────

Scan report for router.local (192.168.1.1)  [2.45s]
  20/20 ports — 3 open, 14 closed, 3 filtered
  PORT      STATE        SERVICE
  ────────────────────────────────────────
  22/tcp    Open         ssh
  80/tcp    Open         http
  443/tcp   Open         https
  ...

────────────────────────────────────────────────────────────
Scan complete in 3.71s
```

---

## Architecture

| File | Responsibility |
|------|---------------|
| `main.rs` | CLI parsing, orchestration, output formatting |
| `scanner.rs` | All scan types: SYN, FIN, NULL, XMAS, ACK, UDP, connect |
| `packet.rs` | Raw packet construction and transport channel management |
| `host_discovery.rs` | ICMP ping sweep + TCP SYN fallback discovery |
| `utils.rs` | Target parsing, port parsing, DNS resolution, service loading, exclusions |

---

## Sensitive DNS Exclusions

The following public DNS servers are always excluded from scans:

| Provider | IPs |
|----------|-----|
| Cloudflare | `1.1.1.1`, `1.0.0.1` |
| Google | `8.8.8.8`, `8.8.4.4` |
| Quad9 | `9.9.9.9`, `149.112.112.112` |
| OpenDNS | `208.67.222.222`, `208.67.220.220` |
| Verisign | `64.6.64.6`, `64.6.65.6` |

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` | CLI argument parsing |
| `tokio` | Async runtime for connect scan |
| `pnet` | Raw packet construction and transport |
| `ipnetwork` | CIDR parsing and iteration |
| `rand` | Random source ports and sequence numbers |
| `indicatif` | Progress bar during host discovery |

---

## Disclaimer

For use only on networks and systems you own or have explicit permission to test.
