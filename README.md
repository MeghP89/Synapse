# synapse

A fast, barebones Rust version of NMap. Supports raw SYN (stealth) scanning and TCP connect scanning, with ICMP host discovery, PTR DNS resolution, and service name lookup.

---

## Features

- **SYN scan** — raw TCP SYN packets via `pnet`, never completes the handshake
- **Connect scan** — full TCP connect, async with configurable concurrency
- **ICMP host discovery** — pings targets before scanning, skips dead hosts
- **PTR DNS resolution** — reverse-resolves IPs to hostnames via Cloudflare (`1.1.1.1`)
- **Service lookup** — maps open ports to service names from `data/nmap-services`
- **Flexible targeting** — single IP, CIDR blocks, octet ranges (e.g. `10.0.0.1-50`), or hostnames
- **Sensitive DNS exclusions** — hardcoded list of public DNS infrastructure that is always excluded from scans
- **Timing** — per-host scan time and total elapsed time printed in output

---

## Requirements

- Rust (edition 2024)
- **Root / CAP_NET_RAW** required for SYN scan and ICMP host discovery (raw sockets)
- `data/nmap-services` file present at runtime (standard nmap-services format)

---

## Build

```bash
cargo build --release
```

---

## Usage

```
sudo ./target/release/synapse [OPTIONS] --target <TARGET>
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | *(required)* | IP, hostname, CIDR, or octet range |
| `--ports` | `-p` | Top 20 common ports | Comma-separated or range (e.g. `80,443` or `1-1024`) |
| `--scan-type` | `-s` | `connect` | `connect` or `syn` |
| `--threads` | | `1000` | Max concurrent tasks (connect scan) |
| `--timeout` | | `500` | Timeout per port in milliseconds |
| `--output` | `true` | Output results to a results dir |

### Examples

```bash
# TCP connect scan a single host on default ports
sudo ./target/release/synapse -t 192.168.1.1

# SYN scan a /24 subnet on ports 22, 80, 443
sudo ./target/release/synapse -t 10.0.0.0/24 -p 22,80,443 -s syn

# Octet range scan
sudo ./target/release/synapse -t 192.168.1.1-50 -p 1-1024

# Scan a hostname with increased timeout
sudo ./target/release/synapse -t example.com --timeout 1000
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
| `scanner.rs` | `stealth_scan` (SYN) and `connect_scan` (TCP connect) |
| `packet.rs` | Raw packet construction and transport channel management |
| `host_discovery.rs` | ICMP echo blast-and-collect with progress bar |
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
