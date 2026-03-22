# synapse

A fast Rust port scanner with raw TCP scan techniques, TLS/HTTP probing, change-diff tracking, UDP scanning, and ICMP + TCP SYN host discovery.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/MeghP89/Synapse/main/install.sh | bash
```

Downloads a pre-built binary for your platform (Linux/macOS × x86_64/aarch64). Falls back to building from source (requires Rust) if no binary is available. Service data is installed to `/usr/local/share/synapse/`.

---

## Features

- **SYN scan** — raw TCP SYN, never completes the handshake
- **FIN / NULL / XMAS scans** — RFC-compliant evasion techniques; report `open|filtered` vs `closed`
- **ACK scan** — maps firewall rules rather than port state
- **UDP scan** — async UDP probe with ICMP port-unreachable detection
- **Connect scan** — full TCP connect, async with configurable concurrency
- **TLS inspection** (`--probe`) — pure-Rust TLS handshake on any open port; extracts cert CN, SAN, issuer, expiry, and TLS version without trusting the cert chain
- **HTTP banner grab** (`--probe`) — inline `GET /` on open ports; extracts status code, `Server` header, and page `<title>`
- **Diff scanning** (`--diff`) — compares current scan against the last saved result for the same target; reports new hosts, lost hosts, and port state changes
- **ICMP host discovery** — ping sweep before scanning, skips dead hosts
- **TCP SYN discovery** — fallback discovery for hosts that block ICMP
- **PTR DNS resolution** — reverse-resolves IPs to hostnames
- **Service lookup** — maps ports to service names from `nmap-services`
- **Flexible targeting** — single IP, CIDR, octet ranges (e.g. `10.0.0.1-50`), or hostnames
- **Sensitive DNS exclusions** — public DNS infrastructure always excluded

---

## Requirements

- **Root / CAP_NET_RAW** required for raw socket scan types (SYN, FIN, NULL, XMAS, ACK) and ICMP discovery
- `connect`, `udp`, `--probe`, and `--diff` work without root

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
| `--probe` | | `false` | TLS inspect + HTTP banner grab on open ports |
| `--diff` | | `false` | Show changes vs last scan for this target |
| `--output` | `-o` | `false` | Save text report to `results/` |
| `--bench` | | `false` | Print performance analysis |

### Scan types

| Type | Flags sent | Requires root | Use case |
|------|-----------|---------------|----------|
| `connect` | — | No | Default; full TCP handshake |
| `syn` | SYN | Yes | Half-open; faster and less logged |
| `fin` | FIN | Yes | Evasion; bypasses some stateless firewalls |
| `null` | *(none)* | Yes | Evasion; same semantics as FIN |
| `xmas` | FIN+PSH+URG | Yes | Evasion; same semantics as FIN |
| `ack` | ACK | Yes | Firewall mapping, not port state |
| `udp` | — (UDP) | No | UDP service discovery |

### Examples

```bash
# Connect scan on default ports
sudo synapse -t 192.168.1.1

# SYN scan a /24 on ports 22, 80, 443
sudo synapse -t 10.0.0.0/24 -p 22,80,443 -s syn

# Connect scan with TLS + HTTP probing
synapse -t 192.168.1.1 -p 80,443,8080,8443 --probe

# Scan and compare against previous results
synapse -t 192.168.1.1 --diff

# FIN scan for stateless firewall evasion
sudo synapse -t 10.0.0.1 -p 1-1024 -s fin

# ACK scan to map firewall rules
sudo synapse -t 10.0.0.1 -p 22,80,443 -s ack

# UDP scan common ports
synapse -t 10.0.0.1 -p 53,67,123,161,500 -s udp

# Octet range scan, save output
sudo synapse -t 192.168.1.1-50 -p 1-1024 -o
```

---

## Output

### Standard scan
```
Starting synapse (Connect scan) against 1 host(s), 20 ports | timeout: 500ms | threads: 1000
────────────────────────────────────────────────────────────

Host Discovery (0.31s)
  [UP  ]  example.com (93.184.216.34)

1 live host(s) to scan
────────────────────────────────────────────────────────────

Scan report for example.com (93.184.216.34)  [1.12s]
  20/20 ports — 2 open, 15 closed, 3 filtered, 0 open|filtered
  PORT      STATE        SERVICE
  ────────────────────────────────────────
  80/tcp    Open         http
  443/tcp   Open         https

────────────────────────────────────────────────────────────
Scan complete in 1.45s
```

### With `--probe`
```
  PORT      STATE        SERVICE        INFO
  ────────────────────────────────────────────────────────────
  80/tcp    Open         http           HTTP 301 | nginx | "301 Moved"
  443/tcp   Open         https          TLS 1.3 | CN:www.example.com | issuer:DigiCert | exp:2026-11-28 | HTTP 200 | ECS | "Example Domain"
```

### With `--diff`
```
Diff vs scan from 2026-03-20 14:32
  [NEW HOST]  10.0.0.5
  [GONE]      10.0.0.3
  [CHANGED]   10.0.0.1:8080 absent → Open
  [CHANGED]   10.0.0.1:23 Open → Closed
```

---

## Architecture

| File | Responsibility |
|------|---------------|
| `main.rs` | CLI parsing, orchestration, output formatting |
| `scanner.rs` | All scan types: SYN, FIN, NULL, XMAS, ACK, UDP, connect |
| `probe.rs` | TLS cert inspection and HTTP banner extraction |
| `diff.rs` | JSON snapshot save/load and diff computation |
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
| `tokio` | Async runtime |
| `pnet` | Raw packet construction and transport |
| `rustls` + `tokio-rustls` | Pure-Rust TLS for cert inspection |
| `x509-parser` | DER certificate parsing |
| `serde` + `serde_json` | JSON snapshot serialization for diff |
| `ipnetwork` | CIDR parsing and iteration |
| `rand` | Random source ports and sequence numbers |
| `indicatif` | Progress bar during host discovery |

---

## Disclaimer

For use only on networks and systems you own or have explicit permission to test.
