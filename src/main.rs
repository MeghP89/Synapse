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

    /// Print a performance/complexity analysis after the scan
    #[arg(long, default_value_t = false)]
    bench: bool,
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

    let ip_to_hostname: std::collections::HashMap<IpAddr, &str> = ips.iter()
        .zip(results.iter())
        .map(|(&ip, hostname)| (ip, hostname.as_str()))
        .collect();

    emit!("\n{} live host(s) to scan", live_ips.len());
    emit!("{}", "─".repeat(60));

    let mut tcp_channels = match args.scan_type {
        ScanType::Syn => Some(open_tcp(&live_ips)),
        ScanType::Connect => None,
    };

    let mut host_scan_times: Vec<(IpAddr, std::time::Duration)> = Vec::new();

    for &ip in live_ips.iter() {
        let hostname = ip_to_hostname.get(&ip).map(|s| s.to_string()).unwrap_or_else(|| ip.to_string());

        let scan_start = Instant::now();
        let ports = match args.scan_type {
            ScanType::Syn => stealth_scan(ip, &target_ports, tcp_channels.as_mut().unwrap()),
            ScanType::Connect => connect_scan(ip, &target_ports, args.timeout, args.threads).await,
        };
        let scan_elapsed = scan_start.elapsed();

        host_scan_times.push((ip, scan_elapsed));
        let scan_result = ScanResult { ip, hostname, ports };

        let (mut n_open, mut n_closed, mut n_filtered) = (0usize, 0usize, 0usize);
        for status in scan_result.ports.values() {
            match status {
                PortStatus::Open     => n_open += 1,
                PortStatus::Closed   => n_closed += 1,
                PortStatus::Filtered => n_filtered += 1,
            }
        }

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

    if args.bench {
        emit_bench(
            &mut report,
            &args.scan_type,
            ips.len(),
            live_ips.len(),
            target_ports.len(),
            args.threads,
            args.timeout,
            &host_scan_times,
        );
    }

    maybe_save(&args.target, &report, args.output);
}

fn emit_bench(
    report: &mut String,
    scan_type: &ScanType,
    total_hosts: usize,
    live_hosts: usize,
    ports: usize,
    threads: usize,
    timeout_ms: u64,
    host_times: &[(IpAddr, std::time::Duration)],
) {
    macro_rules! out {
        ($($arg:tt)*) => {{
            let line = format!($($arg)*);
            println!("{}", line);
            report.push_str(&line);
            report.push('\n');
        }};
    }

    let probe_space = live_hosts * ports;
    let timeout_s = timeout_ms as f64 / 1000.0;

    // Theoretical bounds for connect scan.
    // Serial: every probe waits up to timeout — O(H × P × timeout)
    let theoretical_serial_s = live_hosts as f64 * ports as f64 * timeout_s;
    // Parallel: ports are batched across threads — O(H × ceil(P/T) × timeout)
    let batches = (ports + threads - 1) / threads; // ceil(P/T)
    let theoretical_parallel_s = live_hosts as f64 * batches as f64 * timeout_s;

    let actual_scan_s: f64 = host_times.iter().map(|(_, d)| d.as_secs_f64()).sum();
    let throughput = if actual_scan_s > 0.0 { probe_space as f64 / actual_scan_s } else { f64::INFINITY };

    // Efficiency: how close actual is to the theoretical parallel lower bound (capped at 100%)
    let efficiency = if actual_scan_s > 0.0 {
        (theoretical_parallel_s / actual_scan_s * 100.0).min(100.0)
    } else {
        100.0
    };

    let saturated = threads >= ports;
    let complexity_note = match scan_type {
        ScanType::Connect => {
            if saturated {
                format!("O(H × timeout)  [T≥P: all {} ports fit in one async batch]", ports)
            } else {
                format!("O(H × ⌈P/T⌉ × timeout)  [⌈{}/{}⌉={} batches per host]", ports, threads, batches)
            }
        }
        ScanType::Syn => format!(
            "O(H × P × 5ms_delay + 5s_window)  [sequential SYN blast + fixed listen window]"
        ),
    };

    out!("\n{}", "─".repeat(60));
    out!("Performance Analysis");
    out!("{}", "─".repeat(60));
    out!("  Scan type          : {:?}", scan_type);
    out!("  Total hosts given  : {}", total_hosts);
    out!("  Live hosts scanned : {}", live_hosts);
    out!("  Ports per host     : {}", ports);
    out!("  Probe space (H×P)  : {} probes", probe_space);
    out!("  Concurrency limit  : {} thread(s)", threads);
    out!("  Timeout per probe  : {}ms", timeout_ms);
    out!("");
    out!("  Complexity class   : {}", complexity_note);
    out!("");
    out!("  --- Time bounds (connect scan model) ---");
    out!("  Theoretical serial : {:.2}s  (no concurrency, O(H×P×t))", theoretical_serial_s);
    out!("  Theoretical min    : {:.2}s  (perfect parallelism, O(H×⌈P/T⌉×t))", theoretical_parallel_s);
    out!("  Actual scan time   : {:.2}s  (summed per-host)", actual_scan_s);
    out!("  Efficiency vs min  : {:.1}%", efficiency);
    out!("  Throughput         : {:.0} probes/s", throughput);
    out!("");
    out!("  --- Per-host breakdown ---");
    out!("  {:<45} {:>10}", "Host", "Scan Time");
    out!("  {}", "─".repeat(57));
    for (ip, dur) in host_times {
        let pps = if dur.as_secs_f64() > 0.0 { ports as f64 / dur.as_secs_f64() } else { f64::INFINITY };
        out!("  {:<45} {:>7.2}s  ({:.0} p/s)", ip.to_string(), dur.as_secs_f64(), pps);
    }
    if host_times.len() > 1 {
        let times: Vec<f64> = host_times.iter().map(|(_, d)| d.as_secs_f64()).collect();
        let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let mean = times.iter().sum::<f64>() / times.len() as f64;
        out!("  {}", "─".repeat(57));
        out!("  {:<45} {:>7.2}s  (min)", "", min);
        out!("  {:<45} {:>7.2}s  (mean)", "", mean);
        out!("  {:<45} {:>7.2}s  (max)", "", max);
    }
    out!("{}", "─".repeat(60));
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
