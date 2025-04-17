use etherparse::SlicedPacket;
use std::net::IpAddr;


pub fn parse_source(packet: &[u8]) -> anyhow::Result<IpAddr> {
    match SlicedPacket::from_ip(packet) {
        Ok(packet) => match packet.net {
            Some(net) => match net {
                etherparse::InternetSlice::Ipv4(ipv4) => Ok(ipv4.header().destination_addr().into()),
                etherparse::InternetSlice::Ipv6(_) => Err(anyhow::anyhow!("IPv6 is not supported")),
                etherparse::InternetSlice::Arp(_) => Err(anyhow::anyhow!("ARP is not supported"))
            },
            None => Err(anyhow::anyhow!("missing network layer"))
        },
        Err(error) => Err(anyhow::Error::from(error))
    }
}
