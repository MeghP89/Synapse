mod host_discovery;
use std::net::IpAddr;

use host_discovery::discover_live_hosts;

mod utils;
use utils::{parse_ports, master_target_parser, dns_resolver, open_icmp, open_tcp};

mod scanner;
use scanner::{scan_ports};

// mod packet;
// use packet::{ScanConfig, build_syn, build_rst, parse_response};

// External
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "rnmap")]
#[command(about = "A barebones Rust port scanner MVP", long_about = None)]
struct Args {
    /// The target IP address or CIDR block (e.g., 192.168.1.1 or 10.0.0.0/24)
    #[arg(short = 't', long)]
    target: String,

    /// Ports to scan (e.g., "80,443" or "1-1024")
    #[arg(short = 'p', long, default_value = "80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900")]
    ports: String,

    /// Type of scan to perform
    #[arg(short = 's', long, value_enum, default_value_t = ScanType::Connect)]
    scan_type: ScanType,

    /// Number of concurrent tasks/threads
    #[arg(long, default_value_t = 100)]
    threads: usize,

    /// Timeout in milliseconds per port connection
    #[arg(long, default_value_t = 500)]
    timeout: u64,
}

#[derive(ValueEnum, Clone, Debug)]
enum ScanType {
    Connect,
    Syn,
}


#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("Target: {}", args.target);
    println!("Ports: {}", args.ports);
    println!("Scan Type: {:?}", args.scan_type);
    println!("Threads: {}", args.threads);
    println!("Timeout: {}ms", args.timeout);

    let ips = master_target_parser(&args.target).unwrap();
    if ips.len() > 1024 {
        eprintln!("Warning: {} IPs is a lot, are you sure? (use --force to proceed)", ips.len());
        return;
    }
    let target_ports = parse_ports(&args.ports).unwrap();

    let results = dns_resolver(&ips).await;

    // ICMP Host Discovery
    let mut icmp_channels = open_icmp(&ips);
    let hosts = discover_live_hosts(&ips, &mut icmp_channels);

    // Collect live hosts
    let live_ips: Vec<IpAddr> = ips.iter()
        .filter(|ip| hosts.get(ip).copied().unwrap_or(false))
        .copied()
        .collect();

    for (ip, hostname) in ips.iter().zip(results.iter()) {
        let is_up = hosts.get(ip).copied().unwrap_or(false);
        if is_up {
            println!("{} ({}) appears to be up", hostname, ip);
        } else {
            println!("{} ({}) appears to be down", hostname, ip);
        }
    }

    if live_ips.is_empty() {
        println!("No live hosts found. Exiting.");
        return;
    }

    // Port Scanning
    let mut tcp_channels = open_tcp(&live_ips);

    for (_i, &ip) in live_ips.iter().enumerate() {
        let hostname = ips.iter()
            .position(|&x| x == ip)
            .map(|idx| results[idx].clone())
            .unwrap_or(ip.to_string());

        println!("\nScan report for {} ({})", hostname, ip);
        println!("{:<10} {}", "PORT", "STATE");

        let port_results = scan_ports(ip, &target_ports, &mut tcp_channels);

        let mut open_ports: Vec<_> = port_results.iter()
            .filter(|(_, status)| **status == scanner::PortStatus::Open)
            .collect();
        open_ports.sort_by_key(|(port, _)| *port);

        for (port, status) in &open_ports {
            println!("{}/tcp     {:?}", port, status);
        }

        if open_ports.is_empty() {
            println!("All {} ports are closed or filtered", target_ports.len());
        }
    }
}