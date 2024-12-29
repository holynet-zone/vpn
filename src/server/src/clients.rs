use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub type HolyIp = IpAddr;
pub type SockIp = IpAddr;


#[derive(Clone)]
pub struct Client {
    pub sock_ip: SockIp,
    pub sock_port: u16,
    pub holy_ip: HolyIp,
    pub last_seen: Instant,
}

pub struct Clients {
    available_ip: RwLock<HashSet<HolyIp>>,
    holy_ip_map: RwLock<HashMap<HolyIp, Client>>,
    sock_ip_map: RwLock<HashMap<SockIp, HolyIp>>,
}

impl Clients {
    pub fn new(network: &Ipv4Addr, prefix: &u8) -> Self {
        let mut available = HashSet::new();
        let base: u32 = u32::from(network.clone());
        let mask = !((1 << (32 - prefix)) - 1);
        let start = base & mask;
        let end = start | !mask;
        
        for ip in start + 1..end {
            available.insert(HolyIp::from(Ipv4Addr::from(ip)));
        }

        Clients {
            available_ip: RwLock::new(available),
            holy_ip_map: RwLock::new(HashMap::new()),
            sock_ip_map: RwLock::new(HashMap::new()),
        }
    }
    
    pub fn add(&self, sock_ip: SockIp, sock_port: u16) -> Option<HolyIp> {
        let available_read = self.available_ip.read().unwrap();
        if let Some(holy_ip) = available_read.iter().next().cloned() {
            drop(available_read);
            self.available_ip.write().unwrap().remove(&holy_ip);
            self.holy_ip_map.write().unwrap().insert(holy_ip, Client {
                sock_ip,
                sock_port,
                holy_ip,
                last_seen: Instant::now(),
            });
            self.sock_ip_map.write().unwrap().insert(sock_ip, holy_ip);
            Some(holy_ip)
        } else {
            None
        }
    }

    pub fn release(&self, holy_ip: &HolyIp) -> Option<Client> {
        self.holy_ip_map.write().unwrap().remove(holy_ip)
            .and_then(|client| {
                self.available_ip.write().unwrap().insert(client.holy_ip);
                self.sock_ip_map.write().unwrap().remove(&client.sock_ip);
                Some(client)
            })
    }
    
    pub fn release_by_sock(&self, sock_ip: &SockIp) -> Option<Client> {
        self.sock_ip_map.write().unwrap().remove(sock_ip)
            .and_then(|ip| self.holy_ip_map.write().unwrap().remove(&ip))
            .and_then(|client| {
                self.available_ip.write().unwrap().insert(client.holy_ip);
                Some(client)
            })
    }
    
    pub fn is_allocated(&self, holy_ip: &HolyIp) -> bool {
        self.holy_ip_map.read().unwrap().contains_key(holy_ip)
    }
    
    pub fn is_client(&self, sock_ip: &SockIp) -> bool {
        self.sock_ip_map.read().unwrap().contains_key(sock_ip)
    }
    
    pub fn get_client(&self, holy_ip: &HolyIp) -> Option<Client> {
        self.holy_ip_map.read().unwrap().get(holy_ip).cloned()
    }
    
    pub fn get_client_by_sock(&self, sock_ip: &SockIp) -> Option<Client> {
        self.sock_ip_map.read().unwrap().get(sock_ip)
            .and_then(|ip| self.holy_ip_map.read().unwrap().get(ip).cloned())
    }

    /// Frees all addresses that have not been used for a specified period of time.
    /// todo: It might be worth stretching out the cleaning process if the blocking is going to have a strong impact on performance.
    fn cleanup(&self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<IpAddr> = self.holy_ip_map.read().unwrap()
            .iter()
            .filter(|&(_, client)| now.duration_since(client.last_seen.clone()) > timeout)
            .map(|(&ip, _)| ip)
            .collect();
        
        let mut holy_ip_map = self.holy_ip_map.write().unwrap();
        let mut available_ip = self.available_ip.write().unwrap();
        let mut sock_ip_map = self.sock_ip_map.write().unwrap();
        for ip in expired {
            holy_ip_map.remove(&ip).and_then(|client| {
                available_ip.insert(client.holy_ip);
                sock_ip_map.remove(&client.sock_ip);
                Some(())
            });
        }
    }

    /// Updates the timestamp for the active IP
    /// todo: It might be worth making a runtime for Clients to perform such tasks more efficiently.
    pub fn touch(&self, holy_ip: &HolyIp) {
       self.holy_ip_map.write().unwrap().get_mut(holy_ip)
            .map(|client| client.last_seen = Instant::now());
    }
    
    pub fn touch_by_sock(&self, sock_ip: &SockIp) {
        self.sock_ip_map.read().unwrap().get(sock_ip)
            .map(|ip| self.touch(ip));
    }
}
