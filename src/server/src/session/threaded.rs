use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, RwLock};
use std::time::Instant;
use sunbeam::protocol::enc::BodyEnc;
use crate::session::generators::ipaddr::IpAddressGenerator;
use crate::session::generators::session::SessionIdGenerator;
use crate::session::utils::increment_ip;
use super::{HolyIp, Session, SessionId};

pub struct Sessions {
    session_gen: Mutex<SessionIdGenerator>,
    ip_gen: Mutex<IpAddressGenerator>,

    username_map: RwLock<HashMap<String, HashSet<SessionId>>>,
    session_map: RwLock<HashMap<SessionId, Session>>,
    holy_ip_map: RwLock<HashMap<HolyIp, SessionId>>,
    sock_addr_map: RwLock<HashMap<SocketAddr, SessionId>>,
}

impl Sessions {
    pub fn new(network: &IpAddr, prefix: &u8) -> Self {
        Sessions {
            session_gen: Mutex::new(SessionIdGenerator::new(1)),
            ip_gen: Mutex::new(IpAddressGenerator::new(increment_ip(*network), *prefix)),
            username_map: RwLock::new(HashMap::new()),
            session_map: RwLock::new(HashMap::new()),
            holy_ip_map: RwLock::new(HashMap::new()),
            sock_addr_map: RwLock::new(HashMap::new()),
        }
    }

    pub fn add(&self, sock_addr: SocketAddr, username: String, enc: BodyEnc, key: Vec<u8>) -> Option<(SessionId, HolyIp)> {
        let session_id = self.session_gen.lock().unwrap().next()?;
        let holy_ip = match self.ip_gen.lock().unwrap().next() {
            Some(ip) => ip,
            None => {
                self.session_gen.lock().unwrap().release(session_id);
                return None;
            }
        };

        self.session_map.write().unwrap().insert(session_id, Session {
            sock_addr: sock_addr.clone(),
            holy_ip,
            last_seen: Instant::now(),
            username: username.clone(),
            enc,
            key
        });
        self.username_map.write().unwrap().entry(username).or_insert(HashSet::new()).insert(session_id);
        self.holy_ip_map.write().unwrap().insert(holy_ip, session_id);
        self.sock_addr_map.write().unwrap().insert(sock_addr, session_id);
        Some((session_id, holy_ip))
    }

    pub fn release<K: ReleaseKey>(&self, key: K) -> Option<Session> {
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
    //     let expired: Vec<IpAddr> = self.holy_ip_map.read().unwrap()
    //         .iter()
    //         .filter(|&(_, client)| now.duration_since(client.last_seen.clone()) > timeout)
    //         .map(|(&ip, _)| ip)
    //         .collect();
    //     
    //     let mut holy_ip_map = self.holy_ip_map.write().unwrap();
    //     let mut available_ip = self.available_ip.write().unwrap();
    //     let mut sock_addr_map = self.sock_addr_map.write().unwrap();
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
    //    self.holy_ip_map.write().unwrap().get_mut(holy_ip)
    //         .map(|client| client.last_seen = Instant::now());
    // }
    // 
    // pub fn touch_by_sock(&self, sock_addr: &SocketAddr) {
    //     self.sock_addr_map.read().unwrap().get(sock_addr)
    //         .map(|ip| self.touch(ip));
    // }
}


trait ReleaseKey {
    fn release(self, context: &Sessions) -> Option<Session>;
}

impl ReleaseKey for HolyIp {
    fn release(self, context: &Sessions) -> Option<Session> {
        context.holy_ip_map.write().unwrap().remove(&self)
            .and_then(|session_id| {
                let client = context.session_map.write().unwrap().remove(&session_id)?;
                context.sock_addr_map.write().unwrap().remove(&client.sock_addr);

                {
                    let mut username_guard = context.username_map.write().unwrap();
                    username_guard.entry(client.username.clone()).and_modify(|set| {
                        set.remove(&session_id);
                    });
                    if username_guard.get(&client.username).unwrap().is_empty() {
                        username_guard.remove(&client.username);
                    }
                }

                context.session_gen.lock().unwrap().release(session_id);
                context.ip_gen.lock().unwrap().release(self);
                Some(client)
            })
    }
}

impl ReleaseKey for SocketAddr {
    fn release(self, context: &Sessions) -> Option<Session> {
        context.sock_addr_map.write().unwrap().remove(&self)
            .and_then(|session_id| {
                let client = context.session_map.write().unwrap().remove(&session_id)?;
                context.holy_ip_map.write().unwrap().remove(&client.holy_ip);

                {
                    let mut username_guard = context.username_map.write().unwrap();
                    username_guard.entry(client.username.clone()).and_modify(|set| {
                        set.remove(&session_id);
                    });
                    if username_guard.get(&client.username).unwrap().is_empty() {
                        username_guard.remove(&client.username);
                    }
                }

                context.session_gen.lock().unwrap().release(session_id);
                context.ip_gen.lock().unwrap().release(client.holy_ip);
                Some(client)
            })
    }
}

impl ReleaseKey for SessionId {
    fn release(self, context: &Sessions) -> Option<Session> {
        context.session_map.write().unwrap().remove(&self)
            .and_then(|client| {
                context.holy_ip_map.write().unwrap().remove(&client.holy_ip);
                context.sock_addr_map.write().unwrap().remove(&client.sock_addr);

                {
                    let mut username_guard = context.username_map.write().unwrap();
                    username_guard.entry(client.username.clone()).and_modify(|set| {
                        set.remove(&self);
                    });
                    if username_guard.get(&client.username).unwrap().is_empty() {
                        username_guard.remove(&client.username);
                    }
                }

                context.ip_gen.lock().unwrap().release(client.holy_ip);
                Some(client)
            })
    }
}


trait IsAllocated {
    fn is_allocated(self, context: &Sessions) -> bool;
}

impl IsAllocated for HolyIp {
    fn is_allocated(self, context: &Sessions) -> bool {
        context.holy_ip_map.read().unwrap().contains_key(&self)
    }
}

impl IsAllocated for SocketAddr {
    fn is_allocated(self, context: &Sessions) -> bool {
        context.sock_addr_map.read().unwrap().contains_key(&self)
    }
}

impl IsAllocated for SessionId {
    fn is_allocated(self, context: &Sessions) -> bool {
        context.session_map.read().unwrap().contains_key(&self)
    }
}

trait GetSession {
    fn get(&self, context: &Sessions) -> Option<Session>;
}

impl GetSession for &HolyIp {
    fn get(&self, context: &Sessions) -> Option<Session> {
        context.holy_ip_map.read().unwrap().get(self).and_then(|session_id| {
            context.session_map.read().unwrap().get(session_id).cloned()
        })
    }
}

impl GetSession for &SocketAddr {
    fn get(&self, context: &Sessions) -> Option<Session> {
        context.sock_addr_map.read().unwrap().get(self)
            .and_then(|session_id| context.session_map.read().unwrap().get(session_id).cloned())
    }
}

impl GetSession for &SessionId {
    fn get(&self, context: &Sessions) -> Option<Session> {
        context.session_map.read().unwrap().get(self).cloned()
    }
}

