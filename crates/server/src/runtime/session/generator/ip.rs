use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use dashmap::DashSet;

pub struct IpAddressGenerator {
    current: IpAddr,
    borrowed: DashSet<IpAddr>,
    prefix: u8,
    start: IpAddr,
    end: IpAddr,
}

pub type HolyIp = IpAddr;

impl IpAddressGenerator {
    pub fn new(start_with: IpAddr, prefix: u8) -> Self {
        let (start, end) = Self::calculate_range(start_with, prefix);
        IpAddressGenerator {
            current: start_with,
            borrowed: DashSet::new(),
            prefix,
            start,
            end,
        }
    }

    pub fn next(&mut self) -> Option<IpAddr> {
        if self.borrowed.len() as u128 >= self.max_addresses() {
            return None;
        }

        let initial = self.current;
        loop {
            if self.borrowed.insert(self.current) {
                return Some(self.current);
            }

            self.current = self.increment_address(&self.current);

            if self.current == initial {
                return None;
            }
        }
    }

    pub fn release(&mut self, address: &IpAddr) {
        self.borrowed.remove(address);
    }

    fn increment_address(&self, address: &IpAddr) -> IpAddr {
        match address {
            IpAddr::V4(ipv4) => {
                let mut octets = ipv4.octets();
                for i in (0..4).rev() {
                    if octets[i] < 255 {
                        octets[i] += 1;
                        break;
                    } else {
                        octets[i] = 0;
                    }
                }
                let new_ip = IpAddr::V4(Ipv4Addr::from(octets));

                if new_ip > self.end {
                    self.start
                } else {
                    new_ip
                }
            }
            IpAddr::V6(ipv6) => {
                let mut segments = ipv6.segments();
                for i in (0..8).rev() {
                    if segments[i] < 0xFFFF {
                        segments[i] += 1;
                        break;
                    } else {
                        segments[i] = 0;
                    }
                }
                let new_ip = IpAddr::V6(Ipv6Addr::from(segments));

                if new_ip > self.end {
                    self.start
                } else {
                    new_ip
                }
            }
        }
    }

    fn max_addresses(&self) -> u128 {
        match self.current {
            IpAddr::V4(_) => 2u128.pow(32 - self.prefix as u32),
            IpAddr::V6(_) => 2u128.pow(128 - self.prefix as u32),
        }
    }

    fn calculate_range(start_with: IpAddr, prefix: u8) -> (IpAddr, IpAddr) {
        match start_with {
            IpAddr::V4(ipv4) => {
                let mask = !0u32 << (32 - prefix);
                let start = u32::from(ipv4) & mask;
                let end = start | !mask;
                (
                    IpAddr::V4(Ipv4Addr::from(start)),
                    IpAddr::V4(Ipv4Addr::from(end)),
                )
            }
            IpAddr::V6(ipv6) => {
                let mask = !0u128 << (128 - prefix);
                let start = u128::from(ipv6) & mask;
                let end = start | !mask;
                (
                    IpAddr::V6(Ipv6Addr::from(start)),
                    IpAddr::V6(Ipv6Addr::from(end)),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_address_generator() {
        let mut generator = IpAddressGenerator::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24);
        let mut addresses = Vec::new();
        for _ in 0..256 {
            addresses.push(generator.next().unwrap());
        }

        assert_eq!(generator.next(), None);
        assert_eq!(addresses.len(), 256);
        assert_eq!(addresses[0], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(addresses[255], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)));

        generator.release(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(generator.next(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0))));
    }

    #[test]
    fn test_ipv6_address_generator() {
        let mut generator = IpAddressGenerator::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            120,
        );
        let mut addresses = Vec::new();
        for _ in 0..256 {
            addresses.push(generator.next().unwrap());
        }

        assert_eq!(generator.next(), None);
        assert_eq!(addresses.len(), 256);
        assert_eq!(
            addresses[0],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
        assert_eq!(
            addresses[255],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 255))
        );

        generator.release(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));
        assert_eq!(
            generator
                .next()
                .unwrap()
                .to_string()
                .contains("2001:db8::"),
            true
        );
        generator.release(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert_eq!(
            generator
                .next()
                .unwrap()
                .to_string()
                .contains("2001:db8::1"),
            true
        );
    }
}


pub fn increment_ip(ip: IpAddr) -> IpAddr {
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
