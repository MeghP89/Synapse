// Personal Packages
mod packet;
use packet::{ScanConfig, build_syn, build_rst, parse_response};

// External
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::env;

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

    let my_config = ScanConfig {
        src_mac: interface.mac.unwrap(),
        dst_mac: MacAddr::broadcast(),
        src_ip: source_ip,
        src_port: 49152,
    };

    

    // ── 2. open a raw datalink channel ──────────────────────────────────────
    //
    // A datalink channel lets us send raw Ethernet frames — no OS TCP stack
    // involved. We're operating below the kernel's networking layer.
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_)  => panic!("Unexpected channel type"),
        Err(e) => panic!("Failed to open channel: {}", e),
    };


    let packet_buf = build_syn(&my_config, target_ip, target_port, 12345);
    match tx.send_to(&packet_buf, None) {
        Some(Ok(_))  => println!("[✓] Packet sent ({} bytes)", packet_buf.len()),
        Some(Err(e)) => eprintln!("[✗] Send error: {}", e),
        None         => eprintln!("[✗] Send returned None"),
    }

    println!("\n--- packet memory layout ---");
    println!("bytes  0-13  : Ethernet header");
    println!("bytes 14-33  : IPv4 header");
    println!("bytes 34-53  : TCP header (SYN flag set at byte 47)");
    println!("total        : {} bytes", packet_buf.len());

    loop {
        match rx.next() {
            Ok(frame) => {
                if let Some(response) = parse_response(frame, my_config.src_port) {
                    if response.is_open {
                        println!("Port {} is OPEN!", response.port);
                    } else {
                        println!("Port {} is CLOSED!", response.port);
                    }
                    break; 
                }
            }
            Err(e) => {
                eprintln!("rx error: {}", e);
                break;
            }
        }
    }

    let rst_packet = build_rst(&my_config, target_ip, target_port, 12346); // seq_num + 1
    match tx.send_to(&rst_packet, None) {
        Some(Ok(_))  => println!("[✓] RST sent to {}:{}", target_ip, target_port),
        Some(Err(e)) => eprintln!("[✗] Send error: {}", e),
        None         => eprintln!("[✗] Nothing sent"),
    }
}