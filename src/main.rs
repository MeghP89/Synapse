mod host_discovery;
use std::net::IpAddr;
use std::time::Instant;

use host_discovery::discover_live_hosts;

mod utils;
use utils::{parse_ports, master_target_parser, dns_resolver, load_services,
            apply_exclusions, sensitive_dns_exclusions, save_results};
use packet::{open_icmp, open_tcp};

mod scanner;
use scanner::{stealth_scan, connect_scan, ScanResult, PortStatus};
mod packet;

// External
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "synapse")]
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
    #[arg(long, default_value_t = 1000)]
    threads: usize,

    /// Timeout in milliseconds per port connection
    #[arg(long, default_value_t = 500)]
    timeout: u64,

    /// Save results to a file in the results/ folder
    #[arg(short = 'o', long, default_value_t = false)]
    output: bool,
}

#[derive(ValueEnum, Clone, Debug)]
enum ScanType {
    Connect,
    Syn,
}


#[tokio::main]
async fn main() {
    let total_start = Instant::now();
    let args = Args::parse();
    let services = load_services("data/nmap-services");

    // emit! prints a line and, if --output is set, appends it to the report buffer.
    let mut report = String::new();
    macro_rules! emit {
        ($($arg:tt)*) => {{
            let line = format!($($arg)*);
            println!("{}", line);
            report.push_str(&line);
            report.push('\n');
        }};
    }

    let raw_ips = master_target_parser(&args.target).unwrap();
    let exclusions = sensitive_dns_exclusions();
    let excluded: Vec<_> = raw_ips.iter()
        .filter(|ip| exclusions.iter().any(|n| n.contains(**ip)))
        .copied()
        .collect();
    if !excluded.is_empty() {
        let list: Vec<_> = excluded.iter().map(|ip| ip.to_string()).collect();
        emit!("Excluded {} sensitive DNS server(s): {}", excluded.len(), list.join(", "));
    }
    let ips = apply_exclusions(raw_ips, &exclusions);
    if ips.len() > 1024 {
        eprintln!("Warning: {} IPs is a lot, are you sure? (use --force to proceed)", ips.len());
        return;
    }
    let target_ports = parse_ports(&args.ports).unwrap();

    emit!("Starting synapse ({:?} scan) against {} host(s), {} ports | timeout: {}ms | threads: {}",
        args.scan_type, ips.len(), target_ports.len(), args.timeout, args.threads);
    emit!("{}", "─".repeat(60));

    // DNS + host discovery
    let discovery_start = Instant::now();
    let results = dns_resolver(&ips).await;
    let mut icmp_channels = open_icmp(&ips);
    let hosts = discover_live_hosts(&ips, &mut icmp_channels);
    let discovery_elapsed = discovery_start.elapsed();

    // Collect live hosts
    let live_ips: Vec<IpAddr> = ips.iter()
        .filter(|ip| hosts.get(ip).copied().unwrap_or(false))
        .copied()
        .collect();

    emit!("\nHost Discovery ({:.2}s)", discovery_elapsed.as_secs_f64());
    for (ip, hostname) in ips.iter().zip(results.iter()) {
        let is_up = hosts.get(ip).copied().unwrap_or(false);
        let marker = if is_up { "UP  " } else { "DOWN" };
        let display = if hostname == &ip.to_string() {
            ip.to_string()
        } else {
            format!("{} ({})", hostname, ip)
        };
        emit!("  [{}]  {}", marker, display);
    }

    if live_ips.is_empty() {
        emit!("\nNo live hosts found. Exiting.");
        emit!("\nDone in {:.2}s", total_start.elapsed().as_secs_f64());
        maybe_save(&args.target, &report, args.output);
        return;
    }

    emit!("\n{} live host(s) to scan", live_ips.len());
    emit!("{}", "─".repeat(60));

    // Port Scanning
    let mut tcp_channels = match args.scan_type {
        ScanType::Syn => Some(open_tcp(&live_ips)),
        ScanType::Connect => None,
    };

    for &ip in live_ips.iter() {
        let hostname = ips.iter()
            .position(|&x| x == ip)
            .map(|idx| results[idx].clone())
            .unwrap_or(ip.to_string());

        let scan_start = Instant::now();
        let ports = match args.scan_type {
            ScanType::Syn => stealth_scan(ip, &target_ports, tcp_channels.as_mut().unwrap()),
            ScanType::Connect => connect_scan(ip, &target_ports, args.timeout, args.threads).await,
        };
        let scan_elapsed = scan_start.elapsed();

        let scan_result = ScanResult { ip, hostname, ports };

        let n_open     = scan_result.ports.values().filter(|s| **s == PortStatus::Open).count();
        let n_closed   = scan_result.ports.values().filter(|s| **s == PortStatus::Closed).count();
        let n_filtered = scan_result.ports.values().filter(|s| **s == PortStatus::Filtered).count();

        let display = if scan_result.hostname == ip.to_string() {
            ip.to_string()
        } else {
            format!("{} ({})", scan_result.hostname, scan_result.ip)
        };

        emit!("\nScan report for {}  [{:.2}s]", display, scan_elapsed.as_secs_f64());
        emit!("  {}/{} ports — {} open, {} closed, {} filtered",
            target_ports.len(), target_ports.len(), n_open, n_closed, n_filtered);
        emit!("  {:<9} {:<12} {}", "PORT", "STATE", "SERVICE");
        emit!("  {}", "─".repeat(40));

        let mut all_ports: Vec<_> = scan_result.ports.iter().collect();
        all_ports.sort_by_key(|(port, _)| *port);

        for (port, status) in &all_ports {
            let service = services.get(port).map(|s| s.as_str()).unwrap_or("unknown");
            let state_str = format!("{:?}", status);
            emit!("  {:<9} {:<12} {}", format!("{}/tcp", port), state_str, service);
        }
    }

    emit!("\n{}", "─".repeat(60));
    emit!("Scan complete in {:.2}s", total_start.elapsed().as_secs_f64());

    maybe_save(&args.target, &report, args.output);
}

fn maybe_save(target: &str, report: &str, enabled: bool) {
    if !enabled {
        return;
    }
    match save_results(target, report) {
        Ok(path) => println!("Results saved to {}", path),
        Err(e)   => eprintln!("Failed to save results: {}", e),
    }
}
