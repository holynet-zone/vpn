use std::collections::HashSet;
use std::net::IpAddr;
use etherparse::SlicedPacket;
use pnet::datalink;
use tun_rs::IntoAddress;

pub fn find_available_ifname(base_name: &str) -> String {
    let interfaces = datalink::interfaces();

    let existing_names: HashSet<String> = interfaces
        .into_iter()
        .map(|iface| iface.name)
        .collect();

    let mut index = 0;
    loop {
        let candidate = format!("{}{}", base_name, index);
        if !existing_names.contains(&candidate) {
            return candidate;
        }

        index += 1;
    }
}

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
        Err(error) => Err(anyhow::anyhow!(error))
    }
}