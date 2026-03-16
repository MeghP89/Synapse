use pnet::packet::Packet;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, checksum};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::transport::{TransportReceiver, TransportSender, icmp_packet_iter};
use indicatif::ProgressBar;

use crate::utils::Channels;

use std::net::IpAddr;
use std::collections::HashMap;

pub fn discover_live_hosts(ips: &[IpAddr], channels: &mut Channels) -> HashMap<IpAddr, bool> {
    let mut results: HashMap<IpAddr, bool> = HashMap::new();
    let bar = ProgressBar::new(ips.len() as u64);

    let v4_ips: Vec<IpAddr> = ips.iter().filter(|ip| ip.is_ipv4()).copied().collect();
    let v6_ips: Vec<IpAddr> = ips.iter().filter(|ip| ip.is_ipv6()).copied().collect();

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
        let mut buf = [0u8; 64];
        let mut packet = MutableEchoRequestPacket::new(&mut buf).unwrap();
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_identifier(1234);
        packet.set_sequence_number(1);
        packet.set_payload(&[0u8; 56]);

        let icmp_packet = IcmpPacket::new(packet.packet()).unwrap();
        let cksum = checksum(&icmp_packet);
        packet.set_checksum(cksum);

        let _ = tx.send_to(packet, ip);
        results.insert(ip, false);
    }

    let mut iter = icmp_packet_iter(rx);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);

    while std::time::Instant::now() < deadline {
        match iter.next_with_timeout(std::time::Duration::from_millis(100)) {
            Ok(Some((packet, addr))) => {
                if packet.get_icmp_type() == IcmpTypes::EchoReply {
                    if results.contains_key(&addr) {
                        results.insert(addr, true);
                        bar.inc(1);
                    }
                }
            }
            _ => continue,
        }
    }

    let unreplied = ips.iter().filter(|ip| !results.get(ip).copied().unwrap_or(false)).count();
    bar.inc(unreplied as u64);
}

