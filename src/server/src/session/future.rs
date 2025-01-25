use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use std::time::Instant;
use async_trait::async_trait;
use sunbeam::protocol::enc::EncAlg;
use sunbeam::protocol::keys::session::SessionKey;
use crate::session::generators::ipaddr::IpAddressGenerator;
use crate::session::generators::session::SessionIdGenerator;
use crate::session::utils::increment_ip;
use super::{HolyIp, Session, SessionId};

#[derive(Clone)]
pub struct Sessions {
    session_gen: Arc<Mutex<SessionIdGenerator>>,
    ip_gen: Arc<Mutex<IpAddressGenerator>>,

    username_map: Arc<RwLock<HashMap<String, HashSet<SessionId>>>>,
    session_map: Arc<RwLock<HashMap<SessionId, Session>>>,
    holy_ip_map: Arc<RwLock<HashMap<HolyIp, SessionId>>>,
    sock_addr_map: Arc<RwLock<HashMap<SocketAddr, SessionId>>>,
    
    pub prefix: u8
}

impl Sessions {
    pub fn new(network: &IpAddr, prefix: &u8) -> Self {
        Sessions {
            session_gen: Arc::new(Mutex::new(SessionIdGenerator::new(1))),
            ip_gen: Arc::new(Mutex::new(IpAddressGenerator::new(increment_ip(*network), *prefix))),
            username_map: Arc::new(RwLock::new(HashMap::new())),
            session_map: Arc::new(RwLock::new(HashMap::new())),
            holy_ip_map: Arc::new(RwLock::new(HashMap::new())),
            sock_addr_map: Arc::new(RwLock::new(HashMap::new())),
            prefix: *prefix
        }
    }

    pub async fn add(&self, sock_addr: SocketAddr, username: String, enc: EncAlg, key: SessionKey) -> Option<(SessionId, HolyIp)> {
        let session_id = self.session_gen.lock().await.next()?;
        let holy_ip = match self.ip_gen.lock().await.next() {
            Some(ip) => ip,
            None => {
                self.session_gen.lock().await.release(session_id);
                return None;
            }
        };

        self.session_map.write().await.insert(session_id, Session {
            sock_addr: sock_addr.clone(),
            holy_ip,
            last_seen: Instant::now(),
            username: username.clone(),
            enc,
            key
        });
        self.username_map.write().await.entry(username).or_insert(HashSet::new()).insert(session_id);
        self.holy_ip_map.write().await.insert(holy_ip, session_id);
        self.sock_addr_map.write().await.insert(sock_addr, session_id);
        Some((session_id, holy_ip))
    }

    pub async fn release<K: ReleaseKey>(&self, key: K) -> Option<Session> {
        key.release(self).await
    }

    pub async fn is_allocated<K: IsAllocated>(&self, key: K) -> bool {
        key.is_allocated(self).await
    }

    pub async fn get<K: GetSession>(&self, key: K) -> Option<Session> {
        key.get(self).await
    }
}

#[async_trait]
trait ReleaseKey {
    async fn release(self, context: &Sessions) -> Option<Session>;
}

#[async_trait]
impl ReleaseKey for HolyIp {
    async fn release(self, context: &Sessions) -> Option<Session> {
        let session_id = context.holy_ip_map.write().await.remove(&self)?;
        let client = context.session_map.write().await.remove(&session_id)?;
        context.sock_addr_map.write().await.remove(&client.sock_addr);
        
        {
            let mut username_guard = context.username_map.write().await;
            username_guard.entry(client.username.clone()).and_modify(|set| {
                set.remove(&session_id);
            });
            if username_guard.get(&client.username).unwrap().is_empty() {
                username_guard.remove(&client.username);
            }
        }

        context.session_gen.lock().await.release(session_id);
        context.ip_gen.lock().await.release(self);
        Some(client)
    }
}

#[async_trait]
impl ReleaseKey for SocketAddr {
    async fn release(self, context: &Sessions) -> Option<Session> {
        let session_id = context.sock_addr_map.write().await.remove(&self)?;
        let client = context.session_map.write().await.remove(&session_id)?;
        context.holy_ip_map.write().await.remove(&client.holy_ip);
        
        {
            let mut username_guard = context.username_map.write().await;
            username_guard.entry(client.username.clone()).and_modify(|set| {
                set.remove(&session_id);
            });
            if username_guard.get(&client.username).unwrap().is_empty() {
                username_guard.remove(&client.username);
            }
        }

        context.session_gen.lock().await.release(session_id);
        context.ip_gen.lock().await.release(client.holy_ip);
        Some(client)
    }
}

#[async_trait]
impl ReleaseKey for SessionId {
    async fn release(self, context: &Sessions) -> Option<Session> {
        let client = context.session_map.write().await.remove(&self)?;
        context.holy_ip_map.write().await.remove(&client.holy_ip);
        context.sock_addr_map.write().await.remove(&client.sock_addr);

        {
            let mut username_guard = context.username_map.write().await;
            username_guard.entry(client.username.clone()).and_modify(|set| {
                set.remove(&self);
            });
            if username_guard.get(&client.username).unwrap().is_empty() {
                username_guard.remove(&client.username);
            }
        }

        context.ip_gen.lock().await.release(client.holy_ip);
        Some(client)
            
    }
}


#[async_trait]
trait IsAllocated {
    async fn is_allocated(self, context: &Sessions) -> bool;
}

#[async_trait]
impl IsAllocated for HolyIp {
    async fn is_allocated(self, context: &Sessions) -> bool {
        context.holy_ip_map.read().await.contains_key(&self)
    }
}

#[async_trait]
impl IsAllocated for SocketAddr {
    async fn is_allocated(self, context: &Sessions) -> bool {
        context.sock_addr_map.read().await.contains_key(&self)
    }
}

#[async_trait]
impl IsAllocated for SessionId {
    async fn is_allocated(self, context: &Sessions) -> bool {
        context.session_map.read().await.contains_key(&self)
    }
}

#[async_trait]
trait GetSession {
    async fn get(&self, context: &Sessions) -> Option<Session>;
}

#[async_trait]
impl GetSession for &HolyIp {
    async fn get(&self, context: &Sessions) -> Option<Session> {
        let session_map_guard = context.session_map.read().await;
        let session_id = context.holy_ip_map.read().await.get(self).cloned()?;
        session_map_guard.get(&session_id).cloned()
    }
}

#[async_trait]
impl GetSession for &SocketAddr {
    async fn get(&self, context: &Sessions) -> Option<Session> {
        let session_map_guard = context.session_map.read().await;
        let session_id = context.sock_addr_map.read().await.get(self).cloned()?;
        session_map_guard.get(&session_id).cloned()
    }
}

#[async_trait]
impl GetSession for &SessionId {
    async fn get(&self, context: &Sessions) -> Option<Session> {
        context.session_map.read().await.get(self).cloned()
    }
}

#[tokio::test]
async fn test_deadlock() {
    let sessions = Arc::new(Sessions::new(&IpAddr::from([192, 168, 0, 1]), &24));

    let sessions1 = Arc::clone(&sessions);
    let task1 = tokio::spawn(async move {
        sessions1.add(
            SocketAddr::from(([192, 168, 0, 1], 8080)), 
            "user1".to_string(), 
            EncAlg::Aes256, 
            SessionKey::generate()
        ).await;
    });

    let sessions2 = Arc::clone(&sessions);
    let task2 = tokio::spawn(async move {
        sessions2.release(HolyIp::from([192, 168, 0, 2])).await;
    });

    let _ = tokio::join!(task1, task2);
}