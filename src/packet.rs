use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket, EthernetPacket};
use pnet::packet::ipv4::{self, MutableIpv4Packet, Ipv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

pub struct ScanConfig {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
}

pub struct PortResponse {
    pub port: u16,
    pub is_open: bool,
}

fn build_packet(
    config: &ScanConfig,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    flags: u8, 
    seq_num: u32,
) -> Vec<u8> {
    let mut packet_buf = vec![0u8; 54];
    {
        let tcp_offset = 34;
        let mut tcp = MutableTcpPacket::new(&mut packet_buf[tcp_offset..]).unwrap();
        tcp.set_source(config.src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(1024);
        let checksum = tcp::ipv4_checksum(&tcp.to_immutable(), &config.src_ip, &dst_ip);
        tcp.set_checksum(checksum);
        println!("[*] TCP flags=SYN src_port={} dst_port={dst_port} seq={seq_num}", config.src_port);
    }

    {
        let ip_offset = 14;
        let mut ip = MutableIpv4Packet::new(&mut packet_buf[ip_offset..]).unwrap();

        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((40) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(config.src_ip);
        ip.set_destination(dst_ip);
        ip.set_flags(ipv4::Ipv4Flags::DontFragment);
        let checksum = ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);

        println!("[*] IPv4 src={} dst={} ttl=64 proto=TCP", config.src_ip, dst_ip);
    }

    {
        let mut eth = MutableEthernetPacket::new(&mut packet_buf[..]).unwrap();
        eth.set_source(config.src_mac);
        eth.set_destination(config.dst_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
        
        println!("[*] Eth  src={} dst={} type=IPv4", config.src_mac, config.dst_mac);
    }
    packet_buf
}

pub fn build_syn(
    config: &ScanConfig,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq_num: u32,
) -> Vec<u8> {
    build_packet(config, dst_ip, dst_port, TcpFlags::SYN, seq_num)
}

pub fn build_rst(
    config: &ScanConfig,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq_num: u32,
) -> Vec<u8> {
    build_packet(config, dst_ip, dst_port, TcpFlags::RST, seq_num)
}

pub fn parse_response(frame: &[u8], our_ip: Ipv4Addr) -> Option<PortResponse> {
    let eth = EthernetPacket::new(frame)?;

    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ip = Ipv4Packet::new(eth.payload())?;
    if ip.get_destination() != our_ip {
        return None;
    }

    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let tcp = TcpPacket::new(ip.payload())?;
    println!("[dbg] TCP dst={} our={} flags={}", tcp.get_destination(), our_ip, tcp.get_flags());


    // if tcp.get_destination() != our_port {
    //     return None;
    // }

    let flags = tcp.get_flags();

    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        Some(PortResponse { port: tcp.get_source(), is_open: true})
    } else if flags & TcpFlags::RST != 0 {
        Some(PortResponse { port: tcp.get_source(), is_open: false })
    } else {
        None
    }
}