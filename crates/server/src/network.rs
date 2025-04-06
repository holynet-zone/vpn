use etherparse::SlicedPacket;
use std::net::IpAddr;
use tun_rs::IntoAddress;


pub fn parse_source(packet: &[u8]) -> anyhow::Result<IpAddr> {
    match SlicedPacket::from_ip(&packet) {
        Ok(packet) => match packet.net {
            Some(net) => match net {
                etherparse::InternetSlice::Ipv4(ipv4) => match &ipv4.header().destination_addr().into_address() {
                    Ok(addr) => Ok(addr.clone()),
                    Err(err) => Err(anyhow::anyhow!("failed to parse IPv4 address: {}", err))
                },
                etherparse::InternetSlice::Ipv6(_) => {
                    Err(anyhow::anyhow!("IPv6 is not supported"))
                },
                etherparse::InternetSlice::Arp(_) => {
                    Err(anyhow::anyhow!("ARP is not supported"))
                }
            },
            None => Err(anyhow::anyhow!("failed to parse IP packet: missing network layer"))
        },
        Err(error) => Err(anyhow::Error::from(error))
    }
}