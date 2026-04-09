use indicatif::ProgressBar;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{TransportReceiver, TransportSender, icmp_packet_iter, tcp_packet_iter};

use crate::packet::Channels;

use std::collections::HashMap;
use std::net::IpAddr;

pub fn discover_live_hosts(ips: &[IpAddr], channels: &mut Channels) -> HashMap<IpAddr, bool> {
    let mut results: HashMap<IpAddr, bool> = HashMap::new();
    let bar = ProgressBar::new(ips.len() as u64);

    let (v4_ips, v6_ips): (Vec<IpAddr>, Vec<IpAddr>) =
        ips.iter().copied().partition(|ip| ip.is_ipv4());

    if !v4_ips.is_empty() {
        if let Some((tx, rx)) = channels.v4.as_mut() {
            blast_and_collect(tx, rx, &v4_ips, &mut results, &bar);
        }
    }

    if !v6_ips.is_empty() {
        if let Some((tx, rx)) = channels.v6.as_mut() {
            blast_and_collect(tx, rx, &v6_ips, &mut results, &bar);
        }
    }

    bar.finish();
    results
}

fn blast_and_collect(
    tx: &mut TransportSender,
    rx: &mut TransportReceiver,
    ips: &[IpAddr],
    results: &mut HashMap<IpAddr, bool>,
    bar: &ProgressBar,
) {
    for &ip in ips {
        let packet =
            MutableEchoRequestPacket::owned(crate::packet::build_icmp_echo_request()).unwrap();
        let _ = tx.send_to(packet, ip);
        results.insert(ip, false);
    }

    let mut iter = icmp_packet_iter(rx);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut remaining = ips.len();

    while std::time::Instant::now() < deadline && remaining > 0 {
        match iter.next_with_timeout(std::time::Duration::from_millis(100)) {
            Ok(Some((packet, addr))) => {
                if packet.get_icmp_type() == IcmpTypes::EchoReply {
                    if let Some(seen) = results.get_mut(&addr) {
                        if !*seen {
                            *seen = true;
                            bar.inc(1);
                            remaining -= 1;
                        }
                    }
                }
            }
            _ => continue,
        }
    }

    bar.inc(remaining as u64);
}

pub fn tcp_syn_discovery(ips: &[IpAddr], channels: &mut Channels) -> HashMap<IpAddr, bool> {
    const PROBE_PORTS: &[u16] = &[80, 443, 22, 445, 8080];

    let mut results: HashMap<IpAddr, bool> = ips.iter().map(|&ip| (ip, false)).collect();

    let (v4_ips, v6_ips): (Vec<IpAddr>, Vec<IpAddr>) =
        ips.iter().copied().partition(|ip| ip.is_ipv4());

    if !v4_ips.is_empty() {
        if let Some((tx, rx)) = channels.v4.as_mut() {
            syn_blast_and_collect(tx, rx, &v4_ips, PROBE_PORTS, &mut results);
        }
    }

    if !v6_ips.is_empty() {
        if let Some((tx, rx)) = channels.v6.as_mut() {
            syn_blast_and_collect(tx, rx, &v6_ips, PROBE_PORTS, &mut results);
        }
    }

    results
}

fn syn_blast_and_collect(
    tx: &mut TransportSender,
    rx: &mut TransportReceiver,
    ips: &[IpAddr],
    probe_ports: &[u16],
    results: &mut HashMap<IpAddr, bool>,
) {
    let (local_v4, local_v6) = crate::scanner::get_local_ips();

    for &ip in ips {
        let src_ip = match ip {
            IpAddr::V4(_) => IpAddr::V4(local_v4.expect("no local v4")),
            IpAddr::V6(_) => IpAddr::V6(local_v6.expect("no local v6")),
        };
        for &port in probe_ports {
            let src_port = rand::random_range(49152..65535u16);
            let packet = crate::packet::build_tcp_packet(src_ip, ip, src_port, port, TcpFlags::SYN);
            let _ = tx.send_to(MutableTcpPacket::owned(packet).unwrap(), ip);
        }
    }

    let mut iter = tcp_packet_iter(rx);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut remaining = results.values().filter(|&&v| !v).count();

    while std::time::Instant::now() < deadline && remaining > 0 {
        match iter.next_with_timeout(std::time::Duration::from_millis(100)) {
            Ok(Some((pkt, addr))) => {
                let flags = pkt.get_flags();
                let is_reply = (flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0)
                    || flags & TcpFlags::RST != 0;
                if is_reply {
                    if let Some(seen) = results.get_mut(&addr) {
                        if !*seen {
                            *seen = true;
                            remaining -= 1;
                        }
                    }
                }
            }
            _ => continue,
        }
    }
}
