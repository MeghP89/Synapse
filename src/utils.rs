use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::time::SystemTime;

pub fn load_services(path: &str) -> HashMap<u16, String> {
    let mut services = HashMap::new();
    let contents = fs::read_to_string(path).unwrap_or_default();
    for line in contents.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let (Some(name), Some(port_proto)) = (parts.next(), parts.next()) {
            if let Some((port_str, "tcp")) = port_proto.split_once('/') {
                if let Ok(port) = port_str.parse::<u16>() {
                    services.insert(port, name.to_string());
                }
            }
        }
    }

    services
}

pub fn parse_ports(port_str: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        if let Some((start_str, end_str)) = part.split_once('-') {
            let start = start_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid start port: {}", start_str))?;
            let end = end_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid end port: {}", end_str))?;
            if start > end {
                return Err(format!("Start port greater than end port: {}", part));
            }
            ports.extend(start..=end);
        } else {
            let port = part
                .parse::<u16>()
                .map_err(|_| format!("Invalid single port: {}", part))?;
            ports.push(port);
        }
    }
    Ok(ports)
}

fn parse_target_addr(ip_raw: &str) -> Result<Vec<IpNetwork>, String> {
    let (host_str, prefix_opt) = match ip_raw.split_once('/') {
        Some((host, prefix_str)) => {
            let prefix: u8 = prefix_str
                .parse()
                .map_err(|_| format!("Invalid CIDR number: {}", prefix_str))?;
            (host, Some(prefix))
        }
        None => (ip_raw, None),
    };

    let mut resolved_ips: Vec<IpAddr> = Vec::new();

    if let Ok(ip) = host_str.parse::<IpAddr>() {
        resolved_ips.push(ip);
    } else {
        let host_with_port = format!("{}:0", host_str);
        match host_with_port.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if prefix_opt.is_some() && addr.ip().is_ipv4() {
                        resolved_ips.push(addr.ip());
                        break;
                    }
                    resolved_ips.push(addr.ip());
                }
            }
            Err(_) => return Err(format!("Failed to resolve target: {}", host_str)),
        }
    }

    if resolved_ips.is_empty() {
        return Err(format!("No IP addresses found for: {}", host_str));
    }

    let mut final_networks = Vec::new();
    for ip in resolved_ips {
        let prefix = match prefix_opt {
            Some(p) => {
                if ip.is_ipv4() && p > 32 {
                    return Err(format!("Invalid IPv4 prefix: /{}", p));
                }
                if ip.is_ipv6() && p > 128 {
                    return Err(format!("Invalid IPv6 prefix: /{}", p));
                }
                p
            }
            None => {
                if ip.is_ipv4() {
                    32
                } else {
                    128
                }
            }
        };
        let network =
            IpNetwork::new(ip, prefix).map_err(|e| format!("Invalid network definition: {}", e))?;

        if !final_networks.contains(&network) {
            final_networks.push(network);
        }
    }
    Ok(final_networks)
}

fn parse_octet_part(part: &str) -> Result<Vec<u8>, String> {
    if part == "-" {
        return Ok((0..=255).collect());
    }

    let mut numbers = Vec::new();

    for piece in part.split(',') {
        if let Some((start_str, end_str)) = piece.split_once('-') {
            let start = if start_str.is_empty() {
                0
            } else {
                start_str.parse::<u8>().map_err(|_| "Bad start octet")?
            };
            let end = if end_str.is_empty() {
                255
            } else {
                end_str.parse::<u8>().map_err(|_| "Bad end octet")?
            };

            if start > end {
                return Err(format!("Invalid range: {}", piece));
            }
            for i in start..=end {
                numbers.push(i);
            }
        } else {
            let num = piece
                .parse::<u8>()
                .map_err(|_| format!("Invalid octet: {}", piece))?;
            numbers.push(num);
        }
    }

    Ok(numbers)
}

fn parse_octet_range(target: &str) -> Result<Vec<IpAddr>, String> {
    let parts: Vec<&str> = target.split('.').collect();
    if parts.len() != 4 {
        return Err("Octet ranges must have exactly 4 parts separated by dots".to_string());
    }

    let octet1 = parse_octet_part(parts[0])?;
    let octet2 = parse_octet_part(parts[1])?;
    let octet3 = parse_octet_part(parts[2])?;
    let octet4 = parse_octet_part(parts[3])?;

    let mut generated_ips =
        Vec::with_capacity(octet1.len() * octet2.len() * octet3.len() * octet4.len());

    for &o1 in &octet1 {
        for &o2 in &octet2 {
            for &o3 in &octet3 {
                for &o4 in &octet4 {
                    generated_ips.push(IpAddr::V4(Ipv4Addr::new(o1, o2, o3, o4)));
                }
            }
        }
    }

    Ok(generated_ips)
}

pub fn apply_exclusions(targets: Vec<IpAddr>, exclusions: &[IpNetwork]) -> Vec<IpAddr> {
    targets
        .into_iter()
        .filter(|ip| {
            !exclusions
                .iter()
                .any(|excluded_net| excluded_net.contains(*ip))
        })
        .collect()
}

/// Hardcoded list of sensitive public DNS infrastructure that should never be scanned.
pub fn sensitive_dns_exclusions() -> Vec<IpNetwork> {
    let addrs: &[&str] = &[
        "1.1.1.1",         // Cloudflare primary
        "1.0.0.1",         // Cloudflare secondary
        "8.8.8.8",         // Google primary
        "8.8.4.4",         // Google secondary
        "9.9.9.9",         // Quad9 primary
        "149.112.112.112", // Quad9 secondary
        "208.67.222.222",  // OpenDNS primary
        "208.67.220.220",  // OpenDNS secondary
        "64.6.64.6",       // Verisign primary
        "64.6.65.6",       // Verisign secondary
    ];
    addrs
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .filter_map(|ip| IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 }).ok())
        .collect()
}

pub fn save_results(target: &str, content: &str) -> Result<String, std::io::Error> {
    fs::create_dir_all("results")?;
    let sanitized = target
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = format!("results/synapse_{}_{}.txt", sanitized, ts);
    fs::write(&path, content)?;
    Ok(path)
}

pub fn master_target_parser(input: &str) -> Result<Vec<IpAddr>, String> {
    if input.contains('-') || input.contains(',') {
        return parse_octet_range(input);
    }
    let networks = parse_target_addr(input)?;
    Ok(networks.into_iter().flat_map(|n| n.iter()).collect())
}

pub async fn dns_resolver(input: &[IpAddr]) -> Vec<String> {
    let mut handles: Vec<tokio::task::JoinHandle<String>> = Vec::with_capacity(input.len());

    for &ip in input {
        handles.push(tokio::spawn(async move {
            resolver(ip).unwrap_or_else(|_| ip.to_string())
        }));
    }

    let mut resolved_addresses = Vec::with_capacity(handles.len());
    for handle in handles {
        resolved_addresses.push(handle.await.unwrap());
    }
    resolved_addresses
}

fn resolver(input: IpAddr) -> Result<String, Box<dyn std::error::Error>> {
    let arpa_domain = match input {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            const HEX: &[u8] = b"0123456789abcdef";
            let mut nibbles = String::with_capacity(63);
            for (i, byte) in v6.octets().iter().rev().enumerate() {
                if i > 0 {
                    nibbles.push('.');
                }
                nibbles.push(HEX[(byte & 0x0F) as usize] as char);
                nibbles.push('.');
                nibbles.push(HEX[((byte >> 4) & 0x0F) as usize] as char);
            }
            format!("{}.ip6.arpa", nibbles)
        }
    };
    let query = build_query(&arpa_domain, 12);
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    let _ = socket.send_to(&query, ("1.1.1.1", 53));
    let mut buf = [0u8; 512];
    let len = socket.recv(&mut buf)?;
    parse_response(&buf[..len])
}

fn build_query(domain: &str, record_type: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(domain.len() + 20);

    buf.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&record_type.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    buf
}

fn parse_response(buf: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let answer_count = u16::from_be_bytes([buf[6], buf[7]]);

    if answer_count == 0 {
        return Err("no PTR record found".into());
    }

    let mut pos = 12;

    loop {
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len >= 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }

    pos += 4;

    if buf[pos] >= 0xC0 {
        pos += 2;
    } else {
        loop {
            let len = buf[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + len;
        }
    }

    pos += 10;

    let hostname = read_name(buf, pos)?;
    Ok(hostname)
}

fn read_name(buf: &[u8], start: usize) -> Result<String, Box<dyn std::error::Error>> {
    let mut labels = Vec::new();
    let mut pos = start;

    loop {
        let len = buf[pos] as usize;

        if len == 0 {
            break;
        }

        if len >= 0xC0 {
            let offset = u16::from_be_bytes([buf[pos] & 0x3F, buf[pos + 1]]) as usize;
            let rest = read_name(buf, offset)?;
            labels.push(rest);
            return Ok(labels.join("."));
        }

        pos += 1;
        let label = std::str::from_utf8(&buf[pos..pos + len])?;
        labels.push(label.to_string());
        pos += len;
    }

    Ok(labels.join("."))
}
