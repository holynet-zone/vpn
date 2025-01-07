use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) fn increment_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let mut addr_u32 = u32::from_be_bytes(octets);
            addr_u32 = addr_u32.wrapping_add(1);
            IpAddr::V4(Ipv4Addr::from(addr_u32))
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.octets();
            let mut addr_u128 = u128::from_be_bytes(segments);
            addr_u128 = addr_u128.wrapping_add(1);
            IpAddr::V6(Ipv6Addr::from(addr_u128))
        }
    }
}
