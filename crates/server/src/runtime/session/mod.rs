mod generator;
pub(crate) mod worker;

use std::{
    net::SocketAddr,
    time::Instant,
    sync::Arc
};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use async_trait::async_trait;
use generator::{
    SessionIdGenerator,
    IpAddressGenerator,
    increment_ip
};


use dashmap::DashMap;
use snow::StatelessTransportState;
use tracing::debug;
use shared::session::{Alg, SessionId};
use shared::time::sec_since_start;
pub(crate) use crate::runtime::session::generator::HolyIp;

pub struct Session {
    pub id: SessionId,
    // Socket addr
    ipv4_data: AtomicU64,  // u32 (IP) + u16 (port) + padding
    ipv6_data: AtomicPtr<(u128, u16)>, // 18 bytes
    is_ipv4: AtomicBool,
    //
    pub last_seen: AtomicU64,
    pub created_at: Instant,
    pub holy_ip: HolyIp,
    pub enc: Alg,
    pub state: StatelessTransportState,
}

impl Session {
    pub fn sock_addr(&self) -> SocketAddr {
        if self.is_ipv4.load(Ordering::Relaxed) {
            let encoded = self.ipv4_data.load(Ordering::Relaxed);
            let ip = ((encoded >> 32) & 0xFFFF_FFFF) as u32;
            let port = (encoded & 0xFFFF) as u16;
            SocketAddr::new(IpAddr::from(ip.to_be_bytes()), port)
        } else {
            let ptr = self.ipv6_data.load(Ordering::Relaxed);
            if ptr.is_null() {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                let (ip_u128, port) = unsafe { *ptr };
                SocketAddr::new(IpAddr::from(ip_u128.to_be_bytes()), port)
            }
        }
    }
}

#[derive(Clone)]
pub struct Sessions {
    sid_gen: Arc<Mutex<SessionIdGenerator>>,
    holy_ip_gen: Arc<Mutex<IpAddressGenerator>>,
    map: Arc<DashMap<SessionId, Arc<Session>>>,
    holy_ip_map: Arc<DashMap<HolyIp, SessionId>>,
}

impl Sessions {
    pub fn new(network: &IpAddr, prefix: u8) -> Self {
        Sessions {
            sid_gen: Arc::new(Mutex::new(SessionIdGenerator::new())),
            holy_ip_gen: Arc::new(Mutex::new(IpAddressGenerator::new(increment_ip(*network), prefix))),
            map: Arc::new(DashMap::new()),
            holy_ip_map: Arc::new(DashMap::new())
        }
    }
    
    pub async fn next_session_id(&self) -> Option<SessionId> {
        self.sid_gen.lock().await.next()
    }

    pub async fn next_holy_ip(&self) -> Option<HolyIp> {
        self.holy_ip_gen.lock().await.next()
    }
    
    /// Warning: only if [`SessionId`] was created manually with [`Sessions::next_session_id`] 
    /// and not passed to [`Sessions::add`]
    pub async fn release_session_id(&self, sid: &SessionId) {
        self.sid_gen.lock().await.release(sid);
    }
    
    /// Warning: only if [`HolyIp`] was created manually with [`Sessions::next_holy_ip`]
    /// and not passed to [`Sessions::add`]
    pub async fn release_holy_ip(&self, holy_ip: &HolyIp) {
        self.holy_ip_gen.lock().await.release(holy_ip);
    }

    pub fn add(
        &self,
        sid: SessionId,
        ip: HolyIp,
        sock_addr: SocketAddr,
        enc: Alg,
        state: StatelessTransportState
    ) {
        let (ipv4_data, ipv6_data, is_ipv4) = match sock_addr {
            SocketAddr::V4(addr_v4) => {
                let ip = u32::from_be_bytes(addr_v4.ip().octets());
                let port = addr_v4.port() as u64;
                let encoded = ((ip as u64) << 32) | port;
                (AtomicU64::new(encoded), AtomicPtr::default(), AtomicBool::new(true))
            },
            SocketAddr::V6(addr_v6) => {
                let ip_bytes = addr_v6.ip().octets();
                let ip = u128::from_be_bytes(ip_bytes);
                let port = addr_v6.port();
                let boxed = Box::new((ip, port));
                let ptr = Box::into_raw(boxed);
                (AtomicU64::new(0), AtomicPtr::new(ptr), AtomicBool::new(false))
            }
        };

        let session = Arc::new(Session {
            id: sid,
            ipv4_data,
            ipv6_data,
            is_ipv4,
            last_seen: AtomicU64::from(sec_since_start()),
            created_at: Instant::now(),
            holy_ip: ip,
            enc,
            state,
        });

        self.map.insert(sid, session);
        self.holy_ip_map.insert(ip, sid);
    }
    pub async fn cleanup_sessions(&self, ttl: Duration) {
        let now = sec_since_start();
        let ttl_ns = ttl.as_secs();

        let expired_sids: Vec<SessionId> = self.map.iter()
            .filter(|entry| {
                now.saturating_sub(entry.value().last_seen.load(Ordering::Relaxed)) > ttl_ns
            })
            .map(|entry| *entry.key())
            .collect();

        let mut holy_ips_to_release = Vec::with_capacity(expired_sids.len());
        let mut session_ids_to_release = Vec::with_capacity(expired_sids.len());

        for sid in expired_sids {
            if let Some((_, session)) = self.map.remove(&sid) {
                if let Some((holy_ip, _)) = self.holy_ip_map.remove(&session.holy_ip) {
                    holy_ips_to_release.push(holy_ip);
                }
                session_ids_to_release.push(sid);
            }
        }

        let mut sid_gen = self.sid_gen.lock().await;
        let mut holy_ip_gen = self.holy_ip_gen.lock().await;

        for sid in session_ids_to_release.iter() {
            sid_gen.release(sid);
        }

        for holy_ip in holy_ips_to_release.iter() {
            holy_ip_gen.release(holy_ip);
        }
        
        debug!("[cleanup_sessions] cleaned up {} sessions", session_ids_to_release.len());
    }

    pub async fn release<K: ReleaseKey>(&self, key: K) {
        key.release(self).await
    }

    pub async fn is_allocated<K: IsAllocated>(&self, key: K) -> bool {
        key.is_allocated(self).await
    }

    pub fn get<K: GetSession>(&self, key: K) -> Option<Arc<Session>> {
        key.get(self)
    }

    pub fn touch(&self, sid: SessionId) {
        if let Some(session) = self.map.get(&sid) {
            session.last_seen.store(sec_since_start(), Ordering::Relaxed);
        }
    }

    pub fn update_sock_addr(&self, sid: SessionId, addr: SocketAddr) {
        if let Some(entry) = self.map.get(&sid) {
            let session = entry.value();

            match addr {
                SocketAddr::V4(addr_v4) => {
                    let ip = u32::from_be_bytes(addr_v4.ip().octets());
                    let port = addr_v4.port() as u64;
                    let encoded = ((ip as u64) << 32) | port;
                    session.ipv4_data.store(encoded, Ordering::Relaxed);
                    session.is_ipv4.store(true, Ordering::Relaxed);
                    
                    let old_ptr = session.ipv6_data.swap(std::ptr::null_mut(), Ordering::Relaxed);
                    if !old_ptr.is_null() {
                        unsafe { drop(Box::from_raw(old_ptr)); }
                    }
                }
                SocketAddr::V6(addr_v6) => {
                    let ip = u128::from_be_bytes(addr_v6.ip().octets());
                    let port = addr_v6.port();
                    let boxed = Box::new((ip, port));
                    let new_ptr = Box::into_raw(boxed);

                    let old_ptr = session.ipv6_data.swap(new_ptr, Ordering::Relaxed);
                    if !old_ptr.is_null() {
                        unsafe { drop(Box::from_raw(old_ptr)); }
                    }

                    session.is_ipv4.store(false, Ordering::Relaxed);
                }
            }
        }
    }
}

#[async_trait]
trait ReleaseKey {
    async fn release(&self, context: &Sessions);
}


#[async_trait]
impl ReleaseKey for SessionId {
    async fn release(&self, context: &Sessions) {
        let holy_ip = context.map.remove(self).map(|(_, session)|{
            context.holy_ip_map.remove(&session.holy_ip);
            session.holy_ip
        });
        if let Some(holy_ip) = holy_ip {
            context.holy_ip_gen.lock().await.release(&holy_ip);
        }
        context.sid_gen.lock().await.release(self);
    }
}


#[async_trait]
trait IsAllocated {
    async fn is_allocated(&self, context: &Sessions) -> bool;
}

#[async_trait]
impl IsAllocated for SessionId {
    async fn is_allocated(&self, context: &Sessions) -> bool {
        context.map.contains_key(self)
    }
}

#[async_trait]
impl IsAllocated for HolyIp {
    async fn is_allocated(&self, context: &Sessions) -> bool {
        context.holy_ip_map.contains_key(self)
    }
}

#[async_trait]
trait GetSession {
    fn get(&self, context: &Sessions) -> Option<Arc<Session>>;
}



impl GetSession for &SessionId {
    fn get(&self, context: &Sessions) -> Option<Arc<Session>> {
        context.map.get(*self).map(|entry| entry.value().clone())
    }
}

impl GetSession for &IpAddr {
    fn get(&self, context: &Sessions) -> Option<Arc<Session>> {
        context.holy_ip_map.get(*self)
            .and_then(|entry| context.map.get(entry.value()).map(|e| e.value().clone()))
    }
}