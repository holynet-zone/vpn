use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashSet;

/// Lock-free IP address pool.
///
/// Addresses are represented internally as `u64` offsets from the subnet base
/// address (sufficient for IPv4 and IPv6 subnets up to /64 in size).
/// `next` and `release` take `&self` so the pool can be shared across tasks
/// without a `Mutex`.
pub struct IpAddressGenerator {
    /// Subnet base address as u128 (uniform representation for V4 and V6).
    start: u128,
    /// Number of addresses in the subnet (saturated at u64::MAX for huge V6 subnets).
    range_size: u64,
    /// Monotonic cursor; taken modulo `range_size` to get the next candidate offset.
    cursor: AtomicU64,
    /// Set of currently allocated offsets.
    borrowed: DashSet<u64>,
    is_v4: bool,
}

pub type HolyIp = IpAddr;

impl IpAddressGenerator {
    pub fn new(start_with: IpAddr, prefix: u8) -> Self {
        let (start, end, is_v4) = Self::subnet_range(start_with, prefix);
        let range_size = (end - start)
            .saturating_add(1)
            .min(u64::MAX as u128) as u64;

        let initial_offset = match start_with {
            IpAddr::V4(v4) => (u32::from(v4) as u128).saturating_sub(start),
            IpAddr::V6(v6) => u128::from(v6).saturating_sub(start),
        }
        .min(u64::MAX as u128) as u64;

        IpAddressGenerator {
            start,
            range_size,
            cursor: AtomicU64::new(initial_offset),
            borrowed: DashSet::new(),
            is_v4,
        }
    }

    pub fn next(&self) -> Option<IpAddr> {
        if self.borrowed.len() as u64 >= self.range_size {
            return None;
        }
        for _ in 0..self.range_size {
            let offset = self.cursor.fetch_add(1, Ordering::Relaxed) % self.range_size;
            if self.borrowed.insert(offset) {
                return Some(self.offset_to_ip(offset));
            }
        }
        None
    }

    pub fn release(&self, address: &IpAddr) {
        if let Some(offset) = self.ip_to_offset(address) {
            self.borrowed.remove(&offset);
        }
    }

    fn offset_to_ip(&self, offset: u64) -> IpAddr {
        let addr = self.start + offset as u128;
        if self.is_v4 {
            IpAddr::V4(Ipv4Addr::from(addr as u32))
        } else {
            IpAddr::V6(Ipv6Addr::from(addr))
        }
    }

    fn ip_to_offset(&self, ip: &IpAddr) -> Option<u64> {
        let addr = match ip {
            IpAddr::V4(v4) => u32::from(*v4) as u128,
            IpAddr::V6(v6) => u128::from(*v6),
        };
        addr.checked_sub(self.start)
            .filter(|&off| off < self.range_size as u128)
            .map(|off| off as u64)
    }

    fn subnet_range(addr: IpAddr, prefix: u8) -> (u128, u128, bool) {
        match addr {
            IpAddr::V4(v4) => {
                let mask = !0u32 << (32 - prefix);
                let base = u32::from(v4) & mask;
                (base as u128, (base | !mask) as u128, true)
            }
            IpAddr::V6(v6) => {
                let mask = !0u128 << (128 - prefix);
                let base = u128::from(v6) & mask;
                (base, base | !mask, false)
            }
        }
    }
}

pub fn increment_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(v4.octets()).wrapping_add(1)))
        }
        IpAddr::V6(v6) => {
            IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(v6.octets()).wrapping_add(1)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_address_generator() {
        let generator = IpAddressGenerator::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24);
        let mut addresses = Vec::new();
        for _ in 0..256 {
            addresses.push(generator.next().unwrap());
        }
        assert_eq!(generator.next(), None);
        assert_eq!(addresses.len(), 256);
        assert_eq!(addresses[0], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(addresses[255], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)));

        generator.release(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(
            generator.next(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)))
        );
    }

    #[test]
    fn test_release_and_reuse() {
        // /30 has 4 addresses; fill the pool completely, then release one.
        // The cursor is monotonic, so the freed slot is found on the wrap-around scan.
        let generator = IpAddressGenerator::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 30);
        let ips: Vec<_> = (0..4).map(|_| generator.next().unwrap()).collect();
        assert!(generator.next().is_none(), "pool must be exhausted");
        generator.release(&ips[0]);
        // Only one slot is free — next() must return exactly that one.
        assert_eq!(generator.next(), Some(ips[0]));
    }

    #[tokio::test]
    async fn test_concurrent_no_duplicates() {
        use std::sync::Arc;
        use tokio::task;

        const TASKS: usize = 16;
        const PER_TASK: usize = 16;

        let pool = Arc::new(IpAddressGenerator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            24,
        ));
        let mut handles = Vec::new();
        for _ in 0..TASKS {
            let g = pool.clone();
            handles.push(task::spawn(async move {
                (0..PER_TASK).filter_map(|_| g.next()).collect::<Vec<_>>()
            }));
        }
        let mut all = std::collections::HashSet::new();
        for h in handles {
            for ip in h.await.unwrap() {
                assert!(all.insert(ip), "duplicate IP: {ip}");
            }
        }
    }
}
