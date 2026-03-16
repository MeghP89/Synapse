use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};

use ipnetwork::IpNetwork;

use pnet::transport::{
    transport_channel, TransportChannelType,
    TransportSender, TransportReceiver,
    TransportProtocol,
};
use pnet::packet::ip::IpNextHeaderProtocols;

pub struct Channels {
    pub v4: Option<(TransportSender, TransportReceiver)>,
    pub v6: Option<(TransportSender, TransportReceiver)>,
}

pub fn open_tcp(ips: &[IpAddr]) -> Channels {
    let has_v4 = ips.iter().any(|ip| ip.is_ipv4());
    let has_v6 = ips.iter().any(|ip| ip.is_ipv6());

    let v4 = if has_v4 {
        Some(transport_channel(
            1024,
            TransportChannelType::Layer4(
                TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)
            )
        ).unwrap())
    } else {
        None
    };

    let v6 = if has_v6 {
        Some(transport_channel(
            1024,
            TransportChannelType::Layer4(
                TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)
            )
        ).unwrap())
    } else {
        None
    };

    Channels { v4, v6 }
}

pub fn open_icmp(ips: &[IpAddr]) -> Channels {
    let has_v4 = ips.iter().any(|ip| ip.is_ipv4());
    let has_v6 = ips.iter().any(|ip| ip.is_ipv6());

    let v4 = if has_v4 {
        Some(transport_channel(
            1024,
            TransportChannelType::Layer4(
                TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)
            )
        ).unwrap())
    } else {
        None
    };

    let v6 = if has_v6 {
        Some(transport_channel(
            1024,
            TransportChannelType::Layer4(
                TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)
            )
        ).unwrap())
    } else {
        None
    };

    Channels { v4, v6 }
}

pub fn parse_ports(port_str: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid range format: {}", part));
            }
            let start = bounds[0].parse::<u16>()
                .map_err(|_| format!("Invalid start port: {}", bounds[0]))?;
            let end = bounds[1].parse::<u16>()
                .map_err(|_| format!("Invalid end port: {}", bounds[1]))?;
            if start > end {
                return Err(format!("Start port greater than end port: {}", part));
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let port = part.parse::<u16>()
                .map_err(|_| format!("Invalid single port: {}", part))?;
            ports.push(port);
        }
    }
    Ok(ports)
}

fn parse_target_addr(ip_raw: &str) -> Result<Vec<IpNetwork>, String> {
    let (host_str, prefix_opt) = match ip_raw.split_once('/') {
        Some((host, prefix_str)) => {
            // Parse the string after the '/' into an 8-bit integer
            let prefix: u8 = prefix_str.parse()
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
            None => if ip.is_ipv4() { 32 } else { 128 },
        };
        let network = IpNetwork::new(ip, prefix)
            .map_err(|e| format!("Invalid network definition: {}", e))?;
        
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
            let start = if start_str.is_empty() { 0 } else { start_str.parse::<u8>().map_err(|_| "Bad start octet")? };
            let end = if end_str.is_empty() { 255 } else { end_str.parse::<u8>().map_err(|_| "Bad end octet")? };
            
            if start > end { return Err(format!("Invalid range: {}", piece)); }
            for i in start..=end {
                numbers.push(i);
            }
        } else {
            let num = piece.parse::<u8>().map_err(|_| format!("Invalid octet: {}", piece))?;
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

    let mut generated_ips = Vec::new();

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

// fn apply_exclusions(targets: Vec<IpAddr>, exclusions: &[IpNetwork]) -> Vec<IpAddr> {
//     targets.into_iter()
//         .filter(|ip| {
//             !exclusions.iter().any(|excluded_net| excluded_net.contains(*ip))
//         })
//         .collect()
// }

pub fn master_target_parser(input: &str) -> Result<Vec<IpAddr>, String> {
    let mut final_ips = Vec::new();

    if input.contains('-') || input.contains(',') {
        let generated_ips = parse_octet_range(input)?;
        final_ips.extend(generated_ips);

    } else {
        
        let networks = parse_target_addr(input)?;
        
        for network in networks {
            for ip in network.iter() {
                final_ips.push(ip);
            }
        }
    }

    Ok(final_ips)
}

pub async fn dns_resolver(input: &Vec<IpAddr>) -> Vec<String> {
    let mut handles: Vec<tokio::task::JoinHandle<String>> = Vec::new();

    for ip in input {
        let ip = *ip;
        let handle = tokio::spawn(async move {
            resolver(ip).unwrap_or_else(|_| ip.to_string())
        });
        handles.push(handle);
    }

    let mut resolved_addresses: Vec<String> = Vec::new();
    for handle in handles {
        resolved_addresses.push(handle.await.unwrap());
    }
    resolved_addresses
}

fn resolver(input: IpAddr) -> Result<String, Box<dyn std::error::Error>> {
    let arpa_domain = match input {
        IpAddr::V4(v4) => {
            let o =v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6.octets()
                .iter()
                .rev()
                .flat_map(|byte| {
                    vec![
                        format!("{:x}", byte & 0x0F),
                        format!("{:x}", (byte >> 4) & 0x0F),
                    ]
                })
                .collect();
            format!("{}.ip6.arpa", nibbles.join("."))
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
    let mut buf = Vec::new();

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
    buf.extend_from_slice(&record_type  .to_be_bytes()); 
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
            if len == 0 { pos += 1; break; }
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
