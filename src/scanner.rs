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


struct RttEstimator {
    srtt: f64,   
    rttvar: f64, 
    rto: f64,    
}

impl RttEstimator {
    fn new() -> Self {
        Self { srtt: 0.0, rttvar: 0.0, rto: 2000.0 }
    }

    fn update(&mut self, rtt_ms: f64) {
        if self.srtt == 0.0 {
            self.srtt = rtt_ms;
            self.rttvar = rtt_ms / 2.0;
        } else {
            self.rttvar = 0.75 * self.rttvar + 0.25 * (self.srtt - rtt_ms).abs();
            self.srtt = 0.875 * self.srtt + 0.125 * rtt_ms;
        }
        self.rto = (self.srtt + 4.0 * self.rttvar).clamp(200.0, 5000.0);
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.rto as u64)
    }
}

pub fn stealth_scan(
    dst_ip: IpAddr,
    dst_ports: &[u16],
    channels: &mut Channels,
) -> HashMap<u16, PortStatus> {
    let (local_v4, local_v6) = get_local_ips();
    let src_ip = match dst_ip {
        IpAddr::V4(_) => IpAddr::V4(local_v4.expect("no local v4")),
        IpAddr::V6(_) => IpAddr::V6(local_v6.expect("no local v6")),
    };
    let (tx, rx) = match dst_ip {
        IpAddr::V4(_) => channels.v4.as_mut().expect("no v4 channel"),
        IpAddr::V6(_) => channels.v6.as_mut().expect("no v6 channel"),
    };

    let mut port_map: HashMap<u16, PortStatus> = HashMap::new();
    // dst_port -> send timestamp; used to measure RTT per probe
    let mut in_flight: HashMap<u16, Instant> = HashMap::new();
    let mut rtt = RttEstimator::new();
    let mut iter = tcp_packet_iter(rx);

    for &dst_port in dst_ports {
        let src_port = rand::random_range(49152..65535);
        let packet = crate::packet::build_tcp_packet(src_ip, dst_ip, src_port, dst_port, TcpFlags::SYN);
        let _ = tx.send_to(MutableTcpPacket::owned(packet).unwrap(), dst_ip);
        port_map.insert(dst_port, PortStatus::Filtered);
        in_flight.insert(dst_port, Instant::now());

        // Opportunistically drain any responses that arrived between sends
        if let Ok(Some((pkt, addr))) = iter.next_with_timeout(Duration::from_millis(1)) {
            if addr == dst_ip {
                let probed_port = pkt.get_source();
                if let Some(send_time) = in_flight.remove(&probed_port) {
                    rtt.update(send_time.elapsed().as_secs_f64() * 1000.0);
                    let flags = pkt.get_flags();
                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                        port_map.insert(probed_port, PortStatus::Open);
                        let rst = crate::packet::build_tcp_packet(src_ip, dst_ip, rand::random_range(49152..65535), probed_port, TcpFlags::RST);
                        let _ = tx.send_to(MutableTcpPacket::owned(rst).unwrap(), dst_ip);
                    } else if flags & TcpFlags::RST != 0 {
                        port_map.insert(probed_port, PortStatus::Closed);
                    }
                }
            }
        }
    }

    // Collect remaining in-flight probes; deadline is derived from the RTT model
    let deadline = Instant::now() + rtt.timeout();
    while Instant::now() < deadline && !in_flight.is_empty() {
        match iter.next_with_timeout(Duration::from_millis(50)) {
            Ok(Some((pkt, addr))) => {
                if addr == dst_ip {
                    let probed_port = pkt.get_source();
                    if let Some(send_time) = in_flight.remove(&probed_port) {
                        rtt.update(send_time.elapsed().as_secs_f64() * 1000.0);
                        let flags = pkt.get_flags();
                        if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                            port_map.insert(probed_port, PortStatus::Open);
                            let rst = crate::packet::build_tcp_packet(src_ip, dst_ip, rand::random_range(49152..65535), probed_port, TcpFlags::RST);
                            let _ = tx.send_to(MutableTcpPacket::owned(rst).unwrap(), dst_ip);
                        } else if flags & TcpFlags::RST != 0 {
                            port_map.insert(probed_port, PortStatus::Closed);
                        }
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

