mod host_discovery;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Instant, SystemTime};

use host_discovery::{discover_live_hosts, tcp_syn_discovery};

mod utils;
use packet::{open_icmp, open_tcp};
use utils::{
    apply_exclusions, dns_resolver, load_services, master_target_parser, parse_ports, save_results,
    sensitive_dns_exclusions,
};

mod scanner;
use scanner::{
    PortStatus, ScanResult, ack_scan, connect_scan, fin_scan, null_scan, stealth_scan, udp_scan,
    xmas_scan,
};
mod packet;

mod probe;
use probe::{ProbeResult, probe_port};

mod diff;
use diff::{
    HostSnapshot, ScanSnapshot, compute_diff, load_latest_snapshot, now_timestamp, save_snapshot,
};

use clap::{Parser, ValueEnum};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Parser, Debug)]
#[command(name = "synapse")]
#[command(about = "A barebones Rust port scanner MVP", long_about = None)]
struct Args {
    #[arg(short = 't', long)]
    target: Option<String>,

    #[arg(
        short = 'p',
        long,
        default_value = "80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900"
    )]
    ports: String,

    #[arg(short = 's', long, value_enum, default_value_t = ScanType::Connect)]
    scan_type: ScanType,

    #[arg(long, default_value_t = 1000)]
    threads: usize,

    #[arg(long, default_value_t = 500)]
    timeout: u64,

    #[arg(short = 'o', long, default_value_t = false)]
    output: bool,

    #[arg(long, default_value_t = false)]
    bench: bool,

    /// Probe open ports for TLS cert info and HTTP banners
    #[arg(long, default_value_t = false)]
    probe: bool,

    /// Compare this scan against the most recent saved scan for the same target
    #[arg(long, default_value_t = false)]
    diff: bool,

    /// Show saved scans from SQLite and exit
    #[arg(long, default_value_t = false)]
    history: bool,

    /// Filter SQLite history rows by target
    #[arg(long)]
    history_target: Option<String>,

    /// Limit number of rows shown with --history
    #[arg(long, default_value_t = 10)]
    history_limit: usize,

    /// Print raw saved report for one SQLite row id and exit
    #[arg(long)]
    history_raw_id: Option<i64>,

    /// Disable SQLite save for this run
    #[arg(long, default_value_t = false)]
    no_sqlite_save: bool,
}

#[derive(ValueEnum, Clone, Debug)]
enum ScanType {
    Connect,
    Syn,
    Fin,
    Null,
    Xmas,
    Ack,
    Udp,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let total_start = Instant::now();
    let args = Args::parse();

    if let Some(row_id) = args.history_raw_id {
        match load_saved_raw_output(row_id) {
            Ok((Some(raw), _db_path)) => {
                println!("{}", raw);
                return;
            }
            Ok((None, db_path)) => {
                eprintln!("No saved scan with id {}", row_id);
                eprintln!("SQLite path: {}", db_path);
                return;
            }
            Err(e) => {
                eprintln!("Failed to load saved raw output: {}", e);
                return;
            }
        }
    }

    if args.history {
        let limit = args.history_limit.clamp(1, 200);
        match list_saved_scans(args.history_target.as_deref(), limit) {
            Ok((rows, db_path)) => render_history(&rows, &db_path),
            Err(e) => eprintln!("Failed to load history: {}", e),
        }
        return;
    }

    let target = match &args.target {
        Some(t) => t.clone(),
        None => {
            eprintln!("--target is required unless using --history/--history-raw-id");
            return;
        }
    };
    let raw_scan_requested = matches!(
        args.scan_type,
        ScanType::Syn | ScanType::Fin | ScanType::Null | ScanType::Xmas | ScanType::Ack
    );
    let has_raw_privileges = has_raw_socket_privileges();
    if raw_scan_requested && !has_raw_privileges {
        eprintln!(
            "Raw scan type {:?} requires CAP_NET_RAW (or root) on Linux.",
            args.scan_type
        );
        print_cap_net_raw_hint();
        return;
    }
    if !has_raw_privileges {
        eprintln!(
            "CAP_NET_RAW not detected: ICMP/TCP-SYN host discovery disabled; continuing in direct scan mode."
        );
        print_cap_net_raw_hint();
    }

    let services = [
        "data/nmap-services",
        "/usr/local/share/synapse/nmap-services",
        "/usr/share/nmap/nmap-services",
    ]
    .iter()
    .find_map(|p| {
        let m = load_services(p);
        if m.is_empty() { None } else { Some(m) }
    })
    .unwrap_or_default();

    let mut report = String::new();
    macro_rules! emit {
        ($($arg:tt)*) => {{
            let line = format!($($arg)*);
            println!("{}", line);
            report.push_str(&line);
            report.push('\n');
        }};
    }

    let raw_ips = master_target_parser(&target).unwrap();
    let exclusions = sensitive_dns_exclusions();
    let excluded: Vec<_> = raw_ips
        .iter()
        .filter(|ip| exclusions.iter().any(|n| n.contains(**ip)))
        .copied()
        .collect();
    if !excluded.is_empty() {
        let list: Vec<_> = excluded.iter().map(|ip| ip.to_string()).collect();
        emit!(
            "Excluded {} sensitive DNS server(s): {}",
            excluded.len(),
            list.join(", ")
        );
    }
    let ips = apply_exclusions(raw_ips, &exclusions);
    if ips.len() > 1024 {
        eprintln!(
            "Warning: {} IPs is a lot, are you sure? (use --force to proceed)",
            ips.len()
        );
        return;
    }
    let target_ports = parse_ports(&args.ports).unwrap();

    let prev_snapshot = if args.diff {
        load_latest_snapshot(&target)
    } else {
        None
    };

    emit!(
        "Starting synapse ({:?} scan) against {} host(s), {} ports | timeout: {}ms | threads: {}",
        args.scan_type,
        ips.len(),
        target_ports.len(),
        args.timeout,
        args.threads
    );
    emit!("{}", "─".repeat(60));

    let discovery_start = Instant::now();
    let results = dns_resolver(&ips).await;
    let hosts: HashMap<IpAddr, bool> = if has_raw_privileges {
        let mut icmp_channels = open_icmp(&ips);
        let mut discovered = discover_live_hosts(&ips, &mut icmp_channels);

        let icmp_down: Vec<IpAddr> = ips
            .iter()
            .filter(|ip| !discovered.get(ip).copied().unwrap_or(false))
            .copied()
            .collect();
        if !icmp_down.is_empty() {
            let mut tcp_disc = open_tcp(&icmp_down);
            for (ip, alive) in tcp_syn_discovery(&icmp_down, &mut tcp_disc) {
                if alive {
                    discovered.insert(ip, true);
                }
            }
        }
        discovered
    } else {
        ips.iter().copied().map(|ip| (ip, true)).collect()
    };

    let discovery_elapsed = discovery_start.elapsed();

    let live_ips: Vec<IpAddr> = ips
        .iter()
        .filter(|ip| hosts.get(ip).copied().unwrap_or(false))
        .copied()
        .collect();

    emit!("\nHost Discovery ({:.2}s)", discovery_elapsed.as_secs_f64());
    if !has_raw_privileges {
        emit!("  [INFO] Raw discovery skipped (missing CAP_NET_RAW), treating targets as up.");
    }
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
        maybe_save(&target, &report, args.output);
        maybe_save_sqlite(
            &target,
            &args.scan_type,
            ips.len(),
            0,
            target_ports.len(),
            args.threads,
            args.timeout,
            args.bench,
            args.output,
            &report,
            args.no_sqlite_save,
        );
        return;
    }

    let ip_to_hostname: HashMap<IpAddr, &str> = ips
        .iter()
        .zip(results.iter())
        .map(|(&ip, hostname)| (ip, hostname.as_str()))
        .collect();

    emit!("\n{} live host(s) to scan", live_ips.len());
    emit!("{}", "─".repeat(60));

    let needs_raw_tcp = matches!(
        args.scan_type,
        ScanType::Syn | ScanType::Fin | ScanType::Null | ScanType::Xmas | ScanType::Ack
    );
    let mut tcp_channels = if needs_raw_tcp {
        Some(open_tcp(&live_ips))
    } else {
        None
    };

    let mut host_scan_times: Vec<(IpAddr, std::time::Duration)> = Vec::new();
    let mut snapshot_hosts: Vec<HostSnapshot> = Vec::new();

    for &ip in live_ips.iter() {
        let hostname = ip_to_hostname
            .get(&ip)
            .map(|s| s.to_string())
            .unwrap_or_else(|| ip.to_string());

        let scan_start = Instant::now();
        let ports = match args.scan_type {
            ScanType::Syn => stealth_scan(ip, &target_ports, tcp_channels.as_mut().unwrap()),
            ScanType::Fin => fin_scan(ip, &target_ports, tcp_channels.as_mut().unwrap()),
            ScanType::Null => null_scan(ip, &target_ports, tcp_channels.as_mut().unwrap()),
            ScanType::Xmas => xmas_scan(ip, &target_ports, tcp_channels.as_mut().unwrap()),
            ScanType::Ack => ack_scan(ip, &target_ports, tcp_channels.as_mut().unwrap()),
            ScanType::Udp => udp_scan(ip, &target_ports, args.timeout, args.threads).await,
            ScanType::Connect => connect_scan(ip, &target_ports, args.timeout, args.threads).await,
        };
        let scan_elapsed = scan_start.elapsed();

        host_scan_times.push((ip, scan_elapsed));

        let port_strs: HashMap<u16, String> = ports
            .iter()
            .map(|(&p, s)| (p, format!("{:?}", s)))
            .collect();
        snapshot_hosts.push(HostSnapshot {
            ip: ip.to_string(),
            hostname: hostname.clone(),
            ports: port_strs,
        });

        let probe_map: HashMap<u16, ProbeResult> = if args.probe {
            let open_ports: Vec<u16> = ports
                .iter()
                .filter(|(_, s)| **s == PortStatus::Open)
                .map(|(&p, _)| p)
                .collect();
            let mut map = HashMap::new();
            for port in open_ports {
                map.insert(port, probe_port(ip, port, args.timeout).await);
            }
            map
        } else {
            HashMap::new()
        };

        let scan_result = ScanResult {
            ip,
            hostname,
            ports,
        };

        let (mut n_open, mut n_closed, mut n_filtered, mut n_open_filtered) =
            (0usize, 0usize, 0usize, 0usize);
        for status in scan_result.ports.values() {
            match status {
                PortStatus::Open => n_open += 1,
                PortStatus::Closed => n_closed += 1,
                PortStatus::Filtered => n_filtered += 1,
                PortStatus::OpenFiltered => n_open_filtered += 1,
            }
        }

        let display = if scan_result.hostname == ip.to_string() {
            ip.to_string()
        } else {
            format!("{} ({})", scan_result.hostname, scan_result.ip)
        };

        emit!(
            "\nScan report for {}  [{:.2}s]",
            display,
            scan_elapsed.as_secs_f64()
        );
        emit!(
            "  {}/{} ports — {} open, {} closed, {} filtered, {} open|filtered",
            target_ports.len(),
            target_ports.len(),
            n_open,
            n_closed,
            n_filtered,
            n_open_filtered
        );

        if args.probe {
            emit!(
                "  {:<9} {:<12} {:<14} {}",
                "PORT",
                "STATE",
                "SERVICE",
                "INFO"
            );
        } else {
            emit!("  {:<9} {:<12} {}", "PORT", "STATE", "SERVICE");
        }
        emit!("  {}", "─".repeat(if args.probe { 60 } else { 40 }));

        let mut all_ports: Vec<_> = scan_result.ports.iter().collect();
        all_ports.sort_by_key(|(port, _)| *port);

        for (port, status) in &all_ports {
            let service = services.get(port).map(|s| s.as_str()).unwrap_or("unknown");
            let state_str = format!("{:?}", status);
            if args.probe {
                let info = probe_map.get(port).map(format_probe).unwrap_or_default();
                emit!(
                    "  {:<9} {:<12} {:<14} {}",
                    format!("{}/tcp", port),
                    state_str,
                    service,
                    info
                );
            } else {
                emit!(
                    "  {:<9} {:<12} {}",
                    format!("{}/tcp", port),
                    state_str,
                    service
                );
            }
        }
    }

    emit!("\n{}", "─".repeat(60));
    emit!(
        "Scan complete in {:.2}s",
        total_start.elapsed().as_secs_f64()
    );

    let snapshot = ScanSnapshot {
        target: target.clone(),
        timestamp: now_timestamp(),
        hosts: snapshot_hosts,
    };

    if let Some(prev) = &prev_snapshot {
        let d = compute_diff(prev, &snapshot);
        if d.new_hosts.is_empty() && d.lost_hosts.is_empty() && d.port_changes.is_empty() {
            emit!("\nDiff: no changes since last scan");
        } else {
            emit!("\nDiff vs scan from {}", ts_label(prev.timestamp));
            for h in &d.new_hosts {
                emit!("  [NEW HOST]  {}", h);
            }
            for h in &d.lost_hosts {
                emit!("  [GONE]      {}", h);
            }
            for c in &d.port_changes {
                emit!("  [CHANGED]   {}:{} {} → {}", c.ip, c.port, c.from, c.to);
            }
        }
    }

    let _ = save_snapshot(&snapshot);

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

    maybe_save(&target, &report, args.output);
    maybe_save_sqlite(
        &target,
        &args.scan_type,
        ips.len(),
        live_ips.len(),
        target_ports.len(),
        args.threads,
        args.timeout,
        args.bench,
        args.output,
        &report,
        args.no_sqlite_save,
    );
}

fn format_probe(p: &ProbeResult) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(tls) = &p.tls {
        parts.push(tls.version.clone());
        if let Some(cn) = &tls.cn {
            parts.push(format!("CN:{}", cn));
        } else if !tls.sans.is_empty() {
            parts.push(format!("SAN:{}", tls.sans[0]));
        }
        if let Some(iss) = &tls.issuer {
            parts.push(format!("issuer:{}", iss));
        }
        if let Some(exp) = &tls.expiry {
            if tls.expired {
                parts.push(format!("exp:{} [!]", exp));
            } else {
                parts.push(format!("exp:{}", exp));
            }
        }
    }
    if let Some(http) = &p.http {
        parts.push(format!("HTTP {}", http.status));
        if let Some(s) = &http.server {
            parts.push(s.clone());
        }
        if let Some(t) = &http.title {
            let t = if t.len() > 40 { &t[..40] } else { t.as_str() };
            parts.push(format!("\"{}\"", t));
        }
    }
    parts.join(" | ")
}

fn ts_label(ts: u64) -> String {
    let secs = ts as i64;
    let z = secs / 86400 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let min = (time_of_day % 3600) / 60;
    format!("{:04}-{:02}-{:02} {:02}:{:02}", year, m, d, h, min)
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
    let theoretical_serial_s = live_hosts as f64 * ports as f64 * timeout_s;
    let batches = (ports + threads - 1) / threads;
    let theoretical_parallel_s = live_hosts as f64 * batches as f64 * timeout_s;

    let actual_scan_s: f64 = host_times.iter().map(|(_, d)| d.as_secs_f64()).sum();
    let throughput = if actual_scan_s > 0.0 {
        probe_space as f64 / actual_scan_s
    } else {
        f64::INFINITY
    };
    let efficiency = if actual_scan_s > 0.0 {
        (theoretical_parallel_s / actual_scan_s * 100.0).min(100.0)
    } else {
        100.0
    };

    let saturated = threads >= ports;
    let complexity_note = match scan_type {
        ScanType::Connect => {
            if saturated {
                format!(
                    "O(H × timeout)  [T≥P: all {} ports fit in one async batch]",
                    ports
                )
            } else {
                format!(
                    "O(H × ⌈P/T⌉ × timeout)  [⌈{}/{}⌉={} batches per host]",
                    ports, threads, batches
                )
            }
        }
        ScanType::Syn | ScanType::Fin | ScanType::Null | ScanType::Xmas | ScanType::Ack => format!(
            "O(H × P × 5ms_delay + 5s_window)  [sequential raw blast + fixed listen window]"
        ),
        ScanType::Udp => {
            if saturated {
                format!(
                    "O(H × timeout)  [T≥P: all {} ports fit in one async batch, UDP]",
                    ports
                )
            } else {
                format!(
                    "O(H × ⌈P/T⌉ × timeout)  [⌈{}/{}⌉={} batches per host, UDP]",
                    ports, threads, batches
                )
            }
        }
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
    out!(
        "  Theoretical serial : {:.2}s  (no concurrency, O(H×P×t))",
        theoretical_serial_s
    );
    out!(
        "  Theoretical min    : {:.2}s  (perfect parallelism, O(H×⌈P/T⌉×t))",
        theoretical_parallel_s
    );
    out!(
        "  Actual scan time   : {:.2}s  (summed per-host)",
        actual_scan_s
    );
    out!("  Efficiency vs min  : {:.1}%", efficiency);
    out!("  Throughput         : {:.0} probes/s", throughput);
    out!("");
    out!("  --- Per-host breakdown ---");
    out!("  {:<45} {:>10}", "Host", "Scan Time");
    out!("  {}", "─".repeat(57));
    for (ip, dur) in host_times {
        let pps = if dur.as_secs_f64() > 0.0 {
            ports as f64 / dur.as_secs_f64()
        } else {
            f64::INFINITY
        };
        out!(
            "  {:<45} {:>7.2}s  ({:.0} p/s)",
            ip.to_string(),
            dur.as_secs_f64(),
            pps
        );
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
        Err(e) => eprintln!("Failed to save results: {}", e),
    }
}

const SQLITE_DB_PATH_PRIMARY: &str = "results/synapse.db";
const SQLITE_DB_PATH_FALLBACK: &str = "synapse.db";

fn maybe_save_sqlite(
    target: &str,
    scan_type: &ScanType,
    total_hosts: usize,
    live_hosts: usize,
    ports: usize,
    threads: usize,
    timeout_ms: u64,
    bench_enabled: bool,
    output_file_enabled: bool,
    raw_output: &str,
    disabled: bool,
) {
    if disabled {
        return;
    }
    match save_scan_to_sqlite(
        target,
        scan_type_label(scan_type),
        total_hosts,
        live_hosts,
        ports,
        threads,
        timeout_ms,
        bench_enabled,
        output_file_enabled,
        raw_output,
    ) {
        Ok((id, db_path)) => println!("Saved SQLite record id {} ({})", id, db_path),
        Err(e) => eprintln!("Failed to save SQLite record: {}", e),
    }
}

fn scan_type_label(scan_type: &ScanType) -> &'static str {
    match scan_type {
        ScanType::Connect => "connect",
        ScanType::Syn => "syn",
        ScanType::Fin => "fin",
        ScanType::Null => "null",
        ScanType::Xmas => "xmas",
        ScanType::Ack => "ack",
        ScanType::Udp => "udp",
    }
}

fn open_history_db() -> Result<(Connection, String), String> {
    let candidates = [SQLITE_DB_PATH_PRIMARY, SQLITE_DB_PATH_FALLBACK];
    let mut errors: Vec<String> = Vec::new();

    for path in candidates {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() && fs::create_dir_all(parent).is_err() {
                errors.push(format!("{}: unable to create parent directory", path));
                continue;
            }
        }

        let conn = match Connection::open(path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: {}", path, e));
                continue;
            }
        };

        if let Err(e) = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                total_hosts INTEGER NOT NULL,
                live_hosts INTEGER NOT NULL,
                ports INTEGER NOT NULL,
                threads INTEGER NOT NULL,
                timeout_ms INTEGER NOT NULL,
                bench_enabled INTEGER NOT NULL,
                output_file_enabled INTEGER NOT NULL,
                raw_output TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_target_created_at ON scans(target, created_at DESC);",
        ) {
            errors.push(format!("{}: {}", path, e));
            continue;
        }

        return Ok((conn, path.to_string()));
    }

    Err(format!("unable to open SQLite DB. {}", errors.join(" | ")))
}

fn save_scan_to_sqlite(
    target: &str,
    scan_type: &str,
    total_hosts: usize,
    live_hosts: usize,
    ports: usize,
    threads: usize,
    timeout_ms: u64,
    bench_enabled: bool,
    output_file_enabled: bool,
    raw_output: &str,
) -> Result<(i64, String), String> {
    let (conn, db_path) = open_history_db()?;
    let created_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    conn.execute(
        "INSERT INTO scans (
            target, scan_type, total_hosts, live_hosts, ports, threads, timeout_ms,
            bench_enabled, output_file_enabled, raw_output, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            target,
            scan_type,
            total_hosts as i64,
            live_hosts as i64,
            ports as i64,
            threads as i64,
            timeout_ms as i64,
            bench_enabled as i64,
            output_file_enabled as i64,
            raw_output,
            created_at
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok((conn.last_insert_rowid(), db_path))
}

struct SavedScanRow {
    id: i64,
    target: String,
    scan_type: String,
    total_hosts: i64,
    live_hosts: i64,
    ports: i64,
    bench_enabled: bool,
    created_at: i64,
}

fn list_saved_scans(
    target_filter: Option<&str>,
    limit: usize,
) -> Result<(Vec<SavedScanRow>, String), String> {
    let (conn, db_path) = open_history_db()?;
    let mut rows = Vec::new();
    if let Some(target) = target_filter {
        let mut stmt = conn
            .prepare(
                "SELECT id, target, scan_type, total_hosts, live_hosts, ports, bench_enabled, created_at
                 FROM scans WHERE target = ?1 ORDER BY created_at DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let mapped = stmt
            .query_map(params![target, limit as i64], |row| {
                Ok(SavedScanRow {
                    id: row.get(0)?,
                    target: row.get(1)?,
                    scan_type: row.get(2)?,
                    total_hosts: row.get(3)?,
                    live_hosts: row.get(4)?,
                    ports: row.get(5)?,
                    bench_enabled: row.get::<_, i64>(6)? != 0,
                    created_at: row.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        for r in mapped {
            rows.push(r.map_err(|e| e.to_string())?);
        }
    } else {
        let mut stmt = conn
            .prepare(
                "SELECT id, target, scan_type, total_hosts, live_hosts, ports, bench_enabled, created_at
                 FROM scans ORDER BY created_at DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let mapped = stmt
            .query_map(params![limit as i64], |row| {
                Ok(SavedScanRow {
                    id: row.get(0)?,
                    target: row.get(1)?,
                    scan_type: row.get(2)?,
                    total_hosts: row.get(3)?,
                    live_hosts: row.get(4)?,
                    ports: row.get(5)?,
                    bench_enabled: row.get::<_, i64>(6)? != 0,
                    created_at: row.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        for r in mapped {
            rows.push(r.map_err(|e| e.to_string())?);
        }
    }
    Ok((rows, db_path))
}

fn load_saved_raw_output(id: i64) -> Result<(Option<String>, String), String> {
    let (conn, db_path) = open_history_db()?;
    let result = conn
        .query_row(
            "SELECT raw_output FROM scans WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    Ok((result, db_path))
}

fn render_history(rows: &[SavedScanRow], db_path: &str) {
    if rows.is_empty() {
        println!("No saved scans found in {}", db_path);
        return;
    }

    println!("Saved Scan History ({})", db_path);
    println!(
        "{:<6} {:<20} {:<8} {:<10} {:<9} {:<7} {:<7} {}",
        "ID", "TARGET", "TYPE", "HOSTS", "LIVE", "PORTS", "BENCH", "WHEN"
    );
    println!("{}", "─".repeat(90));
    for row in rows {
        println!(
            "{:<6} {:<20} {:<8} {:<10} {:<9} {:<7} {:<7} {}",
            row.id,
            clip(&row.target, 20),
            row.scan_type,
            row.total_hosts,
            row.live_hosts,
            row.ports,
            if row.bench_enabled { "yes" } else { "no" },
            ts_label(row.created_at as u64),
        );
    }
    println!("\nUse --history-raw-id <ID> to print raw output for one saved scan.");
}

fn clip(input: &str, max: usize) -> String {
    if input.chars().count() <= max {
        return input.to_string();
    }
    let mut s = input
        .chars()
        .take(max.saturating_sub(3))
        .collect::<String>();
    s.push_str("...");
    s
}

#[cfg(target_os = "linux")]
fn has_raw_socket_privileges() -> bool {
    is_effective_root_linux() || has_cap_net_raw_linux()
}

#[cfg(not(target_os = "linux"))]
fn has_raw_socket_privileges() -> bool {
    true
}

#[cfg(target_os = "linux")]
fn is_effective_root_linux() -> bool {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(first) = rest.split_whitespace().next() {
                return first == "0";
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn has_cap_net_raw_linux() -> bool {
    const CAP_NET_RAW_BIT: u32 = 13;
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cap_eff_hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .or_else(|| status.lines().find_map(|line| line.strip_prefix("CapEff:")));
    let Some(hex) = cap_eff_hex else {
        return false;
    };
    let mask = match u128::from_str_radix(hex.trim(), 16) {
        Ok(m) => m,
        Err(_) => return false,
    };
    (mask & (1u128 << CAP_NET_RAW_BIT)) != 0
}

#[cfg(target_os = "linux")]
fn print_cap_net_raw_hint() {
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/usr/local/bin/synapse".to_string());
    eprintln!("Grant capability once with:");
    eprintln!("  sudo setcap cap_net_raw+ep {}", exe);
}

#[cfg(not(target_os = "linux"))]
fn print_cap_net_raw_hint() {}
