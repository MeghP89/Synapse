use crate::utils::{Channels};
use std::net::{IpAddr};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use pnet::packet::tcp::TcpFlags;
use pnet::transport::tcp_packet_iter;
use pnet::{datalink, packet::tcp::{MutableTcpPacket, ipv4_checksum, ipv6_checksum}};

#[derive(Debug, Clone, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

// pub struct ScanResult {
//     pub ip: IpAddr,
//     pub hostname: String,
//     pub ports: HashMap<u16, PortStatus>,
// }

pub fn scan_ports(
    dst_ip: IpAddr,
    dst_ports: &[u16],
    channels: &mut Channels
) -> HashMap<u16, PortStatus> {
    let (local_v4, local_v6) = get_local_ips();
    println!("Local IPs: v4={:?} v6={:?}", local_v4, local_v6);

    let src_ip = match dst_ip {
        IpAddr::V4(_) => {
            IpAddr::V4(local_v4.expect("no local v4"))
        }
        IpAddr::V6(_) => {
            IpAddr::V6(local_v6.expect("no local v6"))
        }
    };
    let (tx, rx) = match dst_ip {
        IpAddr::V4(_) => channels.v4.as_mut().expect("no v4 channel"),
        IpAddr::V6(_) => channels.v6.as_mut().expect("no v6 channel"),
    };
    let mut port_map: HashMap<u16, PortStatus> = HashMap::new();
    for port in dst_ports {
        let src_port = rand::random_range(49152..65535);
        let packet = build_packet(src_ip, dst_ip, src_port, *port, TcpFlags::SYN);
        let tcp_packet = MutableTcpPacket::owned(packet).unwrap();
        let _ = tx.send_to(tcp_packet, dst_ip);
        port_map.insert(*port, PortStatus::Filtered);
        std::thread::sleep(Duration::from_millis(5));
    };

    let mut iter = tcp_packet_iter(rx);
    let deadline = Instant::now() + Duration::from_secs(5);

    while Instant::now() < deadline {
        match iter.next_with_timeout(Duration::from_millis(100)) {
            Ok(Some((packet, addr))) => {
                if addr != dst_ip {
                    continue;
                }

                let src_port = packet.get_source();
                let flags = packet.get_flags();

                if port_map.contains_key(&src_port) {
                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                        port_map.insert(src_port, PortStatus::Open);
                        let packet = build_packet(src_ip, dst_ip, rand::random_range(49152..65535), src_port, TcpFlags::RST);
                        let tcp_packet = MutableTcpPacket::owned(packet).unwrap();
                        let _ = tx.send_to(tcp_packet, dst_ip);
                    } else if flags & TcpFlags::RST != 0 {
                        port_map.insert(src_port, PortStatus::Closed);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => println!("Recv error: {}", e),
        }
    }
    port_map
} 

fn get_local_ips() -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>) {
    let mut v4 = None;
    let mut v6 = None;

    for iface in datalink::interfaces() {
        // Skip loopback and down interfaces
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        for ip in &iface.ips {
            match ip.ip() {
                IpAddr::V4(addr) if v4.is_none() => {
                    v4 = Some(addr);
                }
                IpAddr::V6(addr) if !addr.is_loopback() && v6.is_none() => {
                    v6 = Some(addr);
                }
                _ => {}
            }
        }
    }

    (v4, v6)
}

fn build_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
) -> Vec<u8> {
    let tcp_len = 20;
    let mut tcp_buf = vec![0u8; tcp_len];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buf).unwrap();

    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(rand::random::<u32>());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(flags);
    tcp_packet.set_window(65535);
    let cksum = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            ipv4_checksum(&tcp_packet.to_immutable(), &src, &dst)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ipv6_checksum(&tcp_packet.to_immutable(), &src, &dst)
        }
        _ => panic!("src and dst must be same IP version"),
    };
    tcp_packet.set_checksum(cksum);

    tcp_buf
}
