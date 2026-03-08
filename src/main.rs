/// synapse onboarding — building and sending a raw TCP SYN packet with pnet
///
/// What this script does:
///   1. Constructs an Ethernet frame by hand
///   2. Wraps an IPv4 packet inside it
///   3. Wraps a TCP SYN segment inside that
///   4. Sends it out a real network interface
///
/// Run with: sudo cargo run -- <interface> <target_ip> <target_port>
/// Example:  sudo cargo run -- eth0 93.184.216.34 80
///
/// You need root/sudo because raw sockets require elevated privileges.

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::env;

// ── packet size constants ────────────────────────────────────────────────────
//
// Packets are just byte buffers. Every "layer" is a fixed-size header
// written into a specific region of those bytes.
//
//  [ Ethernet header 14B ][ IPv4 header 20B ][ TCP header 20B ]
//
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN:     usize = 20;
const TCP_HEADER_LEN:      usize = 20;
const TOTAL_LEN:           usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: sudo cargo run -- <interface> <target_ip> <target_port>");
        eprintln!("       sudo cargo run -- eth0 93.184.216.34 80");
        std::process::exit(1);
    }

    let iface_name  = &args[1];
    let target_ip:   Ipv4Addr = args[2].parse().expect("Invalid target IP");
    let target_port: u16      = args[3].parse().expect("Invalid port number");

    // ── 1. find the network interface ───────────────────────────────────────
    //
    // pnet works at the interface level — you pick which NIC to send from.
    // Each interface has a MAC address (layer 2) and an IP address (layer 3).
    let interfaces = datalink::interfaces();
    let interface: NetworkInterface = interfaces
        .into_iter()
        .find(|iface| iface.name == *iface_name)
        .expect(&format!("Interface '{}' not found", iface_name));

    // grab our source IP from the interface
    let source_ip = interface
        .ips
        .iter()
        .find_map(|ip| if let std::net::IpAddr::V4(v4) = ip.ip() { Some(v4) } else { None })
        .expect("No IPv4 address on interface");

    println!("[*] Interface : {}", interface.name);
    println!("[*] Source IP  : {}", source_ip);
    println!("[*] Target     : {}:{}", target_ip, target_port);

    // ── 2. open a raw datalink channel ──────────────────────────────────────
    //
    // A datalink channel lets us send raw Ethernet frames — no OS TCP stack
    // involved. We're operating below the kernel's networking layer.
    let (mut tx, _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_)  => panic!("Unexpected channel type"),
        Err(e) => panic!("Failed to open channel: {}", e),
    };

    // ── 3. allocate our packet buffer ───────────────────────────────────────
    //
    // The entire packet — all three layers — lives in one contiguous byte array.
    // pnet gives us "MutableXPacket" wrappers that let us write fields into
    // specific byte offsets without doing the math ourselves.
    let mut packet_buf = vec![0u8; TOTAL_LEN];

    // ── 4. build the TCP segment (innermost layer first) ────────────────────
    //
    // TCP header lives at offset (ETHERNET + IPV4) in the buffer.
    // Fields we care about for a SYN:
    //   - source port : arbitrary, we pick 49152 (ephemeral range)
    //   - dest port   : the port we're probing
    //   - sequence    : random-ish starting number (we use 12345)
    //   - flags       : SYN bit set (0x002) — this is what makes it a SYN packet
    //   - window      : how many bytes we're willing to receive (65535 = max)
    //   - checksum    : computed over a "pseudo-header" + TCP header
    {
        let tcp_offset = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
        let mut tcp = MutableTcpPacket::new(&mut packet_buf[tcp_offset..]).unwrap();

        tcp.set_source(49152);       // our source port
        tcp.set_destination(target_port);
        tcp.set_sequence(12345);     // starting sequence number
        tcp.set_acknowledgement(0);  // 0 for SYN (nothing to ack yet)
        tcp.set_data_offset(5);      // header length in 32-bit words (5 * 4 = 20 bytes)
        tcp.set_flags(TcpFlags::SYN);// ← the key bit: this marks it as a SYN packet
        tcp.set_window(65535);       // advertise max receive window

        // checksum must be computed AFTER all other fields are set.
        // it's a ones-complement sum over a pseudo-header (src ip, dst ip,
        // protocol, tcp length) + the tcp header itself.
        let checksum = tcp::ipv4_checksum(&tcp.to_immutable(), &source_ip, &target_ip);
        tcp.set_checksum(checksum);

        println!("[*] TCP  flags=SYN src_port=49152 dst_port={} seq=12345", target_port);
    }

    // ── 5. build the IPv4 packet (middle layer) ──────────────────────────────
    //
    // IPv4 header wraps the TCP segment. Key fields:
    //   - version     : 4 (IPv4, not IPv6)
    //   - IHL         : header length in 32-bit words (5 = 20 bytes, no options)
    //   - TTL         : time-to-live, each router decrements; 64 is standard
    //   - next_level_protocol : TCP = 6
    //   - checksum    : over the IP header only (not the payload)
    {
        let ip_offset = ETHERNET_HEADER_LEN;
        let mut ip = MutableIpv4Packet::new(&mut packet_buf[ip_offset..]).unwrap();

        ip.set_version(4);
        ip.set_header_length(5);                           // 5 * 4 = 20 bytes
        ip.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(source_ip);
        ip.set_destination(target_ip);
        ip.set_flags(ipv4::Ipv4Flags::DontFragment);

        // IP checksum covers only the IP header, not the TCP payload
        let checksum = ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);

        println!("[*] IPv4 src={} dst={} ttl=64 proto=TCP", source_ip, target_ip);
    }

    // ── 6. build the Ethernet frame (outermost layer) ────────────────────────
    //
    // Ethernet wraps everything. It needs MAC addresses, not IPs.
    //   - source MAC      : our interface's MAC
    //   - destination MAC : ff:ff:ff:ff:ff:ff (broadcast) — in a real scanner
    //                       you'd ARP for the gateway's MAC instead
    //   - ethertype       : 0x0800 = IPv4
    {
        let mut eth = MutableEthernetPacket::new(&mut packet_buf[..]).unwrap();

        eth.set_source(interface.mac.unwrap());
        eth.set_destination(MacAddr::broadcast()); // broadcast for simplicity
        eth.set_ethertype(EtherTypes::Ipv4);

        println!("[*] Eth  src={} dst=ff:ff:ff:ff:ff:ff type=IPv4", interface.mac.unwrap());
    }

    // ── 7. send it ───────────────────────────────────────────────────────────
    //
    // We hand the raw bytes to the datalink channel. The NIC puts them on the wire.
    // No OS TCP stack is involved — the kernel never sees this as a "connection".
    match tx.send_to(&packet_buf, None) {
        Some(Ok(_))  => println!("[✓] Packet sent ({} bytes)", TOTAL_LEN),
        Some(Err(e)) => eprintln!("[✗] Send error: {}", e),
        None         => eprintln!("[✗] Send returned None"),
    }

    println!("\n--- packet memory layout ---");
    println!("bytes  0-13  : Ethernet header");
    println!("bytes 14-33  : IPv4 header");
    println!("bytes 34-53  : TCP header (SYN flag set at byte 47)");
    println!("total        : {} bytes", TOTAL_LEN);
}