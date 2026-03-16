use pnet::packet::tcp::{MutableTcpPacket, ipv4_checksum, ipv6_checksum};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, checksum};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::Packet;
use pnet::transport::{
    transport_channel, TransportChannelType,
    TransportSender, TransportReceiver,
    TransportProtocol,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::IpAddr;

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

pub fn build_tcp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; 20];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buf).unwrap();

    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(rand::random::<u32>());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(flags);
    tcp_packet.set_window(65535);
    let cksum = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => ipv4_checksum(&tcp_packet.to_immutable(), &src, &dst),
        (IpAddr::V6(src), IpAddr::V6(dst)) => ipv6_checksum(&tcp_packet.to_immutable(), &src, &dst),
        _ => panic!("src and dst must be same IP version"),
    };
    tcp_packet.set_checksum(cksum);
    tcp_buf
}

pub fn build_icmp_echo_request() -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    {
        let mut packet = MutableEchoRequestPacket::new(&mut buf).unwrap();
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_identifier(1234);
        packet.set_sequence_number(1);
        packet.set_payload(&[0u8; 56]);
        let icmp_packet = IcmpPacket::new(packet.packet()).unwrap();
        let cksum = checksum(&icmp_packet);
        packet.set_checksum(cksum);
    }
    buf
}
