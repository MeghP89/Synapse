use crate::packet::{Channels};
use std::net::{IpAddr};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant};

use pnet::packet::tcp::TcpFlags;
use pnet::transport::tcp_packet_iter;
use pnet::{datalink, packet::tcp::MutableTcpPacket};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tokio::net::TcpStream;
#[derive(Debug, Clone, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

pub struct ScanResult {
    pub ip: IpAddr,
    pub hostname: String,
    pub ports: HashMap<u16, PortStatus>,
}

pub fn stealth_scan(
    dst_ip: IpAddr,
    dst_ports: &[u16],
    channels: &mut Channels
) -> HashMap<u16, PortStatus> {
    let (local_v4, local_v6) = get_local_ips();
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
        let packet = crate::packet::build_tcp_packet(src_ip, dst_ip, src_port, *port, TcpFlags::SYN);
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
                        let packet = crate::packet::build_tcp_packet(src_ip, dst_ip, rand::random_range(49152..65535), src_port, TcpFlags::RST);
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

pub async fn connect_scan(
    dst_ip: IpAddr,
    dst_ports: &[u16],
    timeout_ms: u64,
    max_threads: usize, 
) -> HashMap<u16, PortStatus> {
    let semaphore = Arc::new(Semaphore::new(max_threads));
    let mut handles = Vec::new();
    for &port in dst_ports {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let addr = SocketAddr::new(dst_ip, port);
            let status = match timeout(
                Duration::from_millis(timeout_ms),
                TcpStream::connect(addr),
            ).await {
                Ok(Ok(_)) => PortStatus::Open,
                Ok(Err(e)) => {
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        PortStatus::Closed
                    } else {
                        PortStatus::Filtered
                    }
                }
                Err(_) => PortStatus::Filtered,
            };
            (port, status)
        });
        handles.push(handle);
    }
    let mut results = HashMap::new();
    for handle in handles {
        let (port, status) = handle.await.unwrap();
        results.insert(port, status);
    }
    results
}

fn get_local_ips() -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>) {
    let mut v4 = None;
    let mut v6 = None;

    for iface in datalink::interfaces() {
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

