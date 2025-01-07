use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use sunbeam::protocol::enc::BodyEnc;
use crate::session::generators::ipaddr::IpAddressGenerator;
use crate::session::generators::session::SessionIdGenerator;
use crate::session::utils::increment_ip;
use super::{HolyIp, Session, SessionId};


pub struct Sessions {
    session_gen: SessionIdGenerator,
    ip_gen: IpAddressGenerator,

    username_map: HashMap<String, HashSet<SessionId>>,
    session_map: HashMap<SessionId, Session>,
    holy_ip_map: HashMap<HolyIp, SessionId>,
    sock_addr_map: HashMap<SocketAddr, SessionId>
}

impl Sessions {
    pub fn new(network: &IpAddr, prefix: &u8) -> Self {
        Sessions {
            session_gen: SessionIdGenerator::new(1),
            ip_gen: IpAddressGenerator::new(increment_ip(*network), *prefix),
            username_map: HashMap::new(),
            session_map: HashMap::new(),
            holy_ip_map: HashMap::new(),
            sock_addr_map: HashMap::new(),
        }
    }

    pub fn add(&mut self, sock_addr: SocketAddr, username: String, enc: BodyEnc, key: Vec<u8>) -> Option<(SessionId, HolyIp)> {
        let session_id = self.session_gen.next()?;
        let holy_ip = match self.ip_gen.next() {
            Some(ip) => ip,
            None => {
                self.session_gen.release(session_id);
                return None;
            }
        };

        self.session_map.insert(session_id, Session {
            sock_addr: sock_addr.clone(),
            holy_ip,
            last_seen: Instant::now(),
            username: username.clone(),
            enc,
            key
        });
        self.username_map.entry(username).or_insert(HashSet::new()).insert(session_id);
        self.holy_ip_map.insert(holy_ip, session_id);
        self.sock_addr_map.insert(sock_addr, session_id);
        Some((session_id, holy_ip))
    }

    pub fn release<K: ReleaseKey>(&mut self, key: K) -> Option<Session> {
        key.release(self)
    }

    pub fn is_allocated<K: IsAllocated>(&self, key: K) -> bool {
        key.is_allocated(self)
    }

    pub fn get<K: GetSession>(&self, key: K) -> Option<Session> {
        key.get(self)
    }

    // /// Frees all addresses that have not been used for a specified period of time.
    // /// todo: It might be worth stretching out the cleaning process if the blocking is going to have a strong impact on performance.
    // fn cleanup(&self, timeout: Duration) {
    //     let now = Instant::now();
    //     let expired: Vec<IpAddr> = self.holy_ip_map
    //         .iter()
    //         .filter(|&(_, client)| now.duration_since(client.last_seen.clone()) > timeout)
    //         .map(|(&ip, _)| ip)
    //         .collect();
    //     
    //     let mut holy_ip_map = self.holy_ip_map;
    //     let mut available_ip = self.available_ip;
    //     let mut sock_addr_map = self.sock_addr_map;
    //     for ip in expired {
    //         holy_ip_map.remove(&ip).and_then(|client| {
    //             available_ip.insert(client.holy_ip);
    //             sock_addr_map.remove(&client.sock_addr);
    //             Some(())
    //         });
    //     }
    // }
    // 
    // /// Updates the timestamp for the active IP
    // /// todo: It might be worth making a runtime for Sessions to perform such tasks more efficiently.
    // pub fn touch(&self, holy_ip: &HolyIp) {
    //    self.holy_ip_map.get_mut(holy_ip)
    //         .map(|client| client.last_seen = Instant::now());
    // }
    // 
    // pub fn touch_by_sock(&self, sock_addr: &SocketAddr) {
    //     self.sock_addr_map.get(sock_addr)
    //         .map(|ip| self.touch(ip));
    // }
}


trait ReleaseKey {
    fn release(self, context: &mut Sessions) -> Option<Session>;
}

impl ReleaseKey for HolyIp {
    fn release(self, context: &mut Sessions) -> Option<Session> {
        context.holy_ip_map.remove(&self)
            .and_then(|session_id| {
                let client = context.session_map.remove(&session_id)?;
                context.sock_addr_map.remove(&client.sock_addr);
                context.username_map.entry(client.username.clone())
                    .and_modify(|set| { 
                        set.remove(&session_id);
                });
                if context.username_map.get(&client.username).unwrap().is_empty() {
                    context.username_map.remove(&client.username);
                }
                
                context.session_gen.release(session_id);
                context.ip_gen.release(self);
                Some(client)
            })
    }
}

impl ReleaseKey for SocketAddr {
    fn release(self, context: &mut Sessions) -> Option<Session> {
        context.sock_addr_map.remove(&self)
            .and_then(|session_id| {
                let client = context.session_map.remove(&session_id)?;
                context.holy_ip_map.remove(&client.holy_ip);
                context.username_map.entry(client.username.clone())
                    .and_modify(|set| {
                        set.remove(&session_id);
                    });
                if context.username_map.get(&client.username).unwrap().is_empty() {
                    context.username_map.remove(&client.username);
                }

                context.session_gen.release(session_id);
                context.ip_gen.release(client.holy_ip);
                Some(client)
            })
    }
}

impl ReleaseKey for SessionId {
    fn release(self, context: &mut Sessions) -> Option<Session> {
        context.session_map.remove(&self)
            .and_then(|client| {
                context.holy_ip_map.remove(&client.holy_ip);
                context.sock_addr_map.remove(&client.sock_addr);
                context.username_map.entry(client.username.clone())
                    .and_modify(|set| {
                        set.remove(&self);
                    });
                if context.username_map.get(&client.username).unwrap().is_empty() {
                    context.username_map.remove(&client.username);
                }

                context.ip_gen.release(client.holy_ip);
                Some(client)
            })
    }
}


trait IsAllocated {
    fn is_allocated(self, context: &Sessions) -> bool;
}

impl IsAllocated for HolyIp {
    fn is_allocated(self, context: &Sessions) -> bool {
        context.holy_ip_map.contains_key(&self)
    }
}

impl IsAllocated for SocketAddr {
    fn is_allocated(self, context: &Sessions) -> bool {
        context.sock_addr_map.contains_key(&self)
    }
}

impl IsAllocated for SessionId {
    fn is_allocated(self, context: &Sessions) -> bool {
        context.session_map.contains_key(&self)
    }
}

trait GetSession {
    fn get(&self, context: &Sessions) -> Option<Session>;
}

impl GetSession for &HolyIp {
    fn get(&self, context: &Sessions) -> Option<Session> {
        context.holy_ip_map.get(self).and_then(|session_id| {
            context.session_map.get(session_id).cloned()
        })
    }
}

impl GetSession for &SocketAddr {
    fn get(&self, context: &Sessions) -> Option<Session> {
        context.sock_addr_map.get(self)
            .and_then(|session_id| context.session_map.get(session_id).cloned())
    }
}

impl GetSession for &SessionId {
    fn get(&self, context: &Sessions) -> Option<Session> {
        context.session_map.get(self).cloned()
    }
}

