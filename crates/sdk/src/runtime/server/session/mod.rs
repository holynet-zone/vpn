mod generator;
pub mod worker;

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use dashmap::DashMap;
use snow::StatelessTransportState;
use tracing::debug;

use crate::protocol::{Alg, SessionId};
use crate::time::sec_since_start;

use generator::{increment_ip, IpAddressGenerator, SessionIdGenerator};
pub use generator::HolyIp;

pub struct Session {
    pub id: SessionId,
    // Socket addr stored lock-free
    ipv4_data: AtomicU64,           // u32 (IP) | u16 (port)
    ipv6_data: AtomicPtr<(u128, u16)>,
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
        if self.is_ipv4.load(Ordering::Acquire) {
            let encoded = self.ipv4_data.load(Ordering::Relaxed);
            let ip = ((encoded >> 32) & 0xFFFF_FFFF) as u32;
            let port = (encoded & 0xFFFF) as u16;
            SocketAddr::new(IpAddr::from(ip.to_be_bytes()), port)
        } else {
            let ptr = self.ipv6_data.load(Ordering::Acquire);
            if ptr.is_null() {
                SocketAddr::new(IpAddr::from(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                let (ip_u128, port) = unsafe { *ptr };
                SocketAddr::new(IpAddr::from(ip_u128.to_be_bytes()), port)
            }
        }
    }
}

#[derive(Clone)]
pub struct Sessions {
    sid_gen: Arc<SessionIdGenerator>,
    holy_ip_gen: Arc<Mutex<IpAddressGenerator>>,
    map: Arc<DashMap<SessionId, Arc<Session>>>,
    holy_ip_map: Arc<DashMap<HolyIp, SessionId>>,
}

impl Sessions {
    pub fn new(network: &IpAddr, prefix: u8) -> Self {
        Sessions {
            sid_gen: Arc::new(SessionIdGenerator::new()),
            holy_ip_gen: Arc::new(Mutex::new(IpAddressGenerator::new(
                increment_ip(*network),
                prefix,
            ))),
            map: Arc::new(DashMap::new()),
            holy_ip_map: Arc::new(DashMap::new()),
        }
    }

    pub fn next_session_id(&self) -> Option<SessionId> {
        self.sid_gen.next()
    }

    pub fn next_holy_ip(&self) -> Option<HolyIp> {
        self.holy_ip_gen.lock().unwrap().next()
    }

    /// Only call if the SessionId was allocated via `next_session_id` but never passed to `add`.
    pub fn release_session_id(&self, sid: &SessionId) {
        self.sid_gen.release(sid);
    }

    /// Only call if the HolyIp was allocated via `next_holy_ip` but never passed to `add`.
    pub fn release_holy_ip(&self, holy_ip: &HolyIp) {
        self.holy_ip_gen.lock().unwrap().release(holy_ip);
    }

    pub fn add(
        &self,
        sid: SessionId,
        ip: HolyIp,
        sock_addr: SocketAddr,
        enc: Alg,
        state: StatelessTransportState,
    ) {
        let (ipv4_data, ipv6_data, is_ipv4) = match sock_addr {
            SocketAddr::V4(addr_v4) => {
                let ip_u32 = u32::from_be_bytes(addr_v4.ip().octets());
                let encoded = ((ip_u32 as u64) << 32) | addr_v4.port() as u64;
                (AtomicU64::new(encoded), AtomicPtr::default(), AtomicBool::new(true))
            }
            SocketAddr::V6(addr_v6) => {
                let ip_u128 = u128::from_be_bytes(addr_v6.ip().octets());
                let boxed = Box::new((ip_u128, addr_v6.port()));
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

    pub fn cleanup_sessions(&self, ttl: Duration) {
        let now = sec_since_start();
        let ttl_secs = ttl.as_secs();

        let expired_sids: Vec<SessionId> = self
            .map
            .iter()
            .filter(|entry| {
                now.saturating_sub(entry.value().last_seen.load(Ordering::Relaxed)) > ttl_secs
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

        for sid in session_ids_to_release.iter() {
            self.sid_gen.release(sid);
        }

        let mut holy_ip_gen = self.holy_ip_gen.lock().unwrap();
        for holy_ip in holy_ips_to_release.iter() {
            holy_ip_gen.release(holy_ip);
        }

        debug!("[cleanup_sessions] cleaned up {} sessions", session_ids_to_release.len());
    }

    pub fn release_by_sid(&self, sid: SessionId) {
        let holy_ip = self.map.remove(&sid).map(|(_, session)| {
            self.holy_ip_map.remove(&session.holy_ip);
            session.holy_ip
        });
        if let Some(holy_ip) = holy_ip {
            self.holy_ip_gen.lock().unwrap().release(&holy_ip);
        }
        self.sid_gen.release(&sid);
    }

    pub fn is_sid_allocated(&self, sid: SessionId) -> bool {
        self.map.contains_key(&sid)
    }

    pub fn is_holy_ip_allocated(&self, ip: &HolyIp) -> bool {
        self.holy_ip_map.contains_key(ip)
    }

    pub fn get_by_sid(&self, sid: &SessionId) -> Option<Arc<Session>> {
        self.map.get(sid).map(|entry| entry.value().clone())
    }

    pub fn get_by_holy_ip(&self, ip: &HolyIp) -> Option<Arc<Session>> {
        self.holy_ip_map
            .get(ip)
            .and_then(|entry| self.map.get(entry.value()).map(|e| e.value().clone()))
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
                    let ip_u32 = u32::from_be_bytes(addr_v4.ip().octets());
                    let encoded = ((ip_u32 as u64) << 32) | addr_v4.port() as u64;
                    session.ipv4_data.store(encoded, Ordering::Relaxed);
                    // Release: ensures ipv4_data write is visible before is_ipv4 flips
                    let old_ptr = session.ipv6_data.swap(std::ptr::null_mut(), Ordering::AcqRel);
                    session.is_ipv4.store(true, Ordering::Release);
                    if !old_ptr.is_null() {
                        unsafe { drop(Box::from_raw(old_ptr)) }
                    }
                }
                SocketAddr::V6(addr_v6) => {
                    let ip_u128 = u128::from_be_bytes(addr_v6.ip().octets());
                    let new_ptr = Box::into_raw(Box::new((ip_u128, addr_v6.port())));
                    // Release: ensures pointer is written before is_ipv4 flips
                    let old_ptr = session.ipv6_data.swap(new_ptr, Ordering::AcqRel);
                    session.is_ipv4.store(false, Ordering::Release);
                    if !old_ptr.is_null() {
                        unsafe { drop(Box::from_raw(old_ptr)) }
                    }
                }
            }
        }
    }
}
