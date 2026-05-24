mod generator;
pub mod worker;

use std::collections::BTreeMap;
use std::sync::{
    Mutex, Mutex as StdMutex,
    atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering},
};
use std::time::Duration;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use dashmap::DashMap;
use snow::StatelessTransportState;
use tracing::debug;

use crate::protocol::{Alg, SessionId};
use crate::runtime::replay::ReplayWindow;
use crate::time::sec_since_start;

pub use generator::HolyIp;
use generator::{IpAddressGenerator, SessionIdGenerator, increment_ip};

pub struct Session {
    pub id: SessionId,
    // Socket addr stored lock-free
    ipv4_data: AtomicU64, // u32 (IP) | u16 (port)
    ipv6_data: AtomicPtr<(u128, u16)>,
    is_ipv4: AtomicBool,
    //
    pub last_seen: AtomicU64,
    pub created_at: Instant,
    pub holy_ip: HolyIp,
    pub enc: Alg,
    pub state: StatelessTransportState,
    /// Monotonically increasing nonce for packets sent by the server to this client.
    pub(crate) send_nonce: AtomicU64,
    /// Anti-replay window for packets received from this client.
    pub(crate) recv_window: Mutex<ReplayWindow>,
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

    /// Update the client's observed socket address directly on the session.
    /// Used by recv workers that already hold an `Arc<Session>` to avoid a
    /// second DashMap lookup.
    pub fn set_sock_addr(&self, addr: SocketAddr) {
        match addr {
            SocketAddr::V4(addr_v4) => {
                let ip_u32 = u32::from_be_bytes(addr_v4.ip().octets());
                let encoded = ((ip_u32 as u64) << 32) | addr_v4.port() as u64;
                self.ipv4_data.store(encoded, Ordering::Relaxed);
                let old_ptr = self.ipv6_data.swap(std::ptr::null_mut(), Ordering::AcqRel);
                self.is_ipv4.store(true, Ordering::Release);
                if !old_ptr.is_null() {
                    unsafe { drop(Box::from_raw(old_ptr)) }
                }
            }
            SocketAddr::V6(addr_v6) => {
                let ip_u128 = u128::from_be_bytes(addr_v6.ip().octets());
                let new_ptr = Box::into_raw(Box::new((ip_u128, addr_v6.port())));
                let old_ptr = self.ipv6_data.swap(new_ptr, Ordering::AcqRel);
                self.is_ipv4.store(false, Ordering::Release);
                if !old_ptr.is_null() {
                    unsafe { drop(Box::from_raw(old_ptr)) }
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Sessions {
    sid_gen: Arc<SessionIdGenerator>,
    holy_ip_gen: Arc<IpAddressGenerator>,
    map: Arc<DashMap<SessionId, Arc<Session>>>,
    holy_ip_map: Arc<DashMap<HolyIp, SessionId>>,
    /// TTL-ordered queue for O(k) cleanup.
    ///
    /// Key = seconds-since-start when the session was inserted or last re-queued.
    /// A session at key T becomes a cleanup candidate when `now >= T + ttl_secs`.
    /// Updated only on `add()` and inside `cleanup_sessions()` (not on `touch()`),
    /// so the hot data path sees zero overhead.
    expiry_queue: Arc<StdMutex<BTreeMap<u64, Vec<SessionId>>>>,
}

impl Sessions {
    pub fn new(network: &IpAddr, prefix: u8) -> Self {
        Sessions {
            sid_gen: Arc::new(SessionIdGenerator::new()),
            holy_ip_gen: Arc::new(IpAddressGenerator::new(increment_ip(*network), prefix)),
            map: Arc::new(DashMap::new()),
            holy_ip_map: Arc::new(DashMap::new()),
            expiry_queue: Arc::new(StdMutex::new(BTreeMap::new())),
        }
    }

    pub fn next_session_id(&self) -> Option<SessionId> {
        self.sid_gen.next()
    }

    pub fn next_holy_ip(&self) -> Option<HolyIp> {
        self.holy_ip_gen.next()
    }

    /// Only call if the SessionId was allocated via `next_session_id` but never passed to `add`.
    pub fn release_session_id(&self, sid: &SessionId) {
        self.sid_gen.release(sid);
    }

    /// Only call if the HolyIp was allocated via `next_holy_ip` but never passed to `add`.
    pub fn release_holy_ip(&self, holy_ip: &HolyIp) {
        self.holy_ip_gen.release(holy_ip);
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
                (
                    AtomicU64::new(encoded),
                    AtomicPtr::default(),
                    AtomicBool::new(true),
                )
            }
            SocketAddr::V6(addr_v6) => {
                let ip_u128 = u128::from_be_bytes(addr_v6.ip().octets());
                let boxed = Box::new((ip_u128, addr_v6.port()));
                let ptr = Box::into_raw(boxed);
                (
                    AtomicU64::new(0),
                    AtomicPtr::new(ptr),
                    AtomicBool::new(false),
                )
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
            send_nonce: AtomicU64::new(0),
            recv_window: Mutex::new(ReplayWindow::new()),
        });

        self.map.insert(sid, session);
        self.holy_ip_map.insert(ip, sid);
        self.expiry_queue
            .lock()
            .unwrap()
            .entry(sec_since_start())
            .or_default()
            .push(sid);
    }

    /// Remove expired sessions in O(k + m) time, where k = candidate sessions
    /// old enough to check, m = still-alive sessions that need re-queuing.
    ///
    /// Sessions inserted less than `ttl` ago are never examined, so steady-state
    /// servers with mostly active clients do near-zero work per cleanup tick.
    pub fn cleanup_sessions(&self, ttl: Duration) {
        let now = sec_since_start();
        let ttl_secs = ttl.as_secs();

        // Pull all queue entries old enough to be candidates (inserted <= ttl ago).
        let cutoff = now.saturating_sub(ttl_secs);
        let candidates: Vec<(u64, Vec<SessionId>)> = {
            let mut queue = self.expiry_queue.lock().unwrap();
            let keys: Vec<u64> = queue.range(..=cutoff).map(|(&k, _)| k).collect();
            keys.into_iter()
                .filter_map(|k| queue.remove(&k).map(|v| (k, v)))
                .collect()
        }; // lock released here

        let mut removed = 0usize;
        let mut requeue: Vec<(u64, SessionId)> = Vec::new();

        for (_insert_time, sids) in candidates {
            for sid in sids {
                let Some(session) = self.map.get(&sid) else {
                    // Already removed by explicit disconnect or prior cleanup.
                    continue;
                };
                let last_seen = session.last_seen.load(Ordering::Relaxed);
                if now.saturating_sub(last_seen) > ttl_secs {
                    // Truly expired.
                    drop(session);
                    if let Some((_, session)) = self.map.remove(&sid) {
                        if let Some((holy_ip, _)) = self.holy_ip_map.remove(&session.holy_ip) {
                            self.holy_ip_gen.release(&holy_ip);
                        }
                        self.sid_gen.release(&sid);
                        removed += 1;
                    }
                } else {
                    // Still alive — re-queue at its current last_seen so we
                    // check again after another TTL duration of inactivity.
                    drop(session);
                    requeue.push((last_seen, sid));
                }
            }
        }

        if !requeue.is_empty() {
            let mut queue = self.expiry_queue.lock().unwrap();
            for (ts, sid) in requeue {
                queue.entry(ts).or_default().push(sid);
            }
        }

        debug!("[cleanup_sessions] removed {} sessions", removed);
    }

    pub fn release_by_sid(&self, sid: SessionId) {
        let holy_ip = self.map.remove(&sid).map(|(_, session)| {
            self.holy_ip_map.remove(&session.holy_ip);
            session.holy_ip
        });
        if let Some(holy_ip) = holy_ip {
            self.holy_ip_gen.release(&holy_ip);
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

    /// Fetch a session and atomically update its `last_seen` timestamp within
    /// the same DashMap read guard — one lookup instead of two.
    pub fn get_and_touch(&self, sid: &SessionId) -> Option<Arc<Session>> {
        let entry = self.map.get(sid)?;
        entry.last_seen.store(sec_since_start(), Ordering::Relaxed);
        Some(entry.value().clone())
    }

    pub fn get_by_holy_ip(&self, ip: &HolyIp) -> Option<Arc<Session>> {
        self.holy_ip_map
            .get(ip)
            .and_then(|entry| self.map.get(entry.value()).map(|e| e.value().clone()))
    }

    pub fn touch(&self, sid: SessionId) {
        if let Some(session) = self.map.get(&sid) {
            session
                .last_seen
                .store(sec_since_start(), Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub fn update_sock_addr(&self, sid: SessionId, addr: SocketAddr) {
        if let Some(entry) = self.map.get(&sid) {
            entry.value().set_sock_addr(addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use snow::StatelessTransportState;

    use super::*;
    use crate::protocol::Alg;
    use crate::runtime::crypto::make_noise_pair_for_test;
    use crate::time::sec_since_start;

    fn make_sessions() -> Sessions {
        Sessions::new(&"10.0.0.0".parse().unwrap(), 8)
    }

    fn add_one(
        sessions: &Sessions,
        addr: SocketAddr,
        state: StatelessTransportState,
    ) -> (SessionId, HolyIp) {
        let sid = sessions.next_session_id().unwrap();
        let ip = sessions.next_holy_ip().unwrap();
        sessions.add(sid, ip, addr, Alg::ChaCha20Poly1305, state);
        (sid, ip)
    }

    // ── add / lookup ───────────────────────────────────────────────────────────

    #[test]
    fn test_add_lookup_by_sid() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let (sid, ip) = add_one(&sessions, "127.0.0.1:1234".parse().unwrap(), state);

        let session = sessions.get_by_sid(&sid).unwrap();
        assert_eq!(session.id, sid);
        assert_eq!(session.holy_ip, ip);
    }

    #[test]
    fn test_add_lookup_by_holy_ip() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let (sid, ip) = add_one(&sessions, "127.0.0.1:1234".parse().unwrap(), state);

        let session = sessions.get_by_holy_ip(&ip).unwrap();
        assert_eq!(session.id, sid);
    }

    #[test]
    fn test_unknown_sid_returns_none() {
        let sessions = make_sessions();
        assert!(sessions.get_by_sid(&0xDEAD_BEEF).is_none());
    }

    // ── release ────────────────────────────────────────────────────────────────

    #[test]
    fn test_release_by_sid_removes_session_and_ip() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let (sid, ip) = add_one(&sessions, "127.0.0.1:1111".parse().unwrap(), state);

        assert!(sessions.is_sid_allocated(sid));
        assert!(sessions.is_holy_ip_allocated(&ip));

        sessions.release_by_sid(sid);

        assert!(!sessions.is_sid_allocated(sid));
        assert!(!sessions.is_holy_ip_allocated(&ip));
    }

    // ── cleanup_sessions ───────────────────────────────────────────────────────

    #[test]
    fn test_cleanup_removes_expired_keeps_fresh() {
        let sessions = make_sessions();

        let (s1, _) = make_noise_pair_for_test();
        let (s2, _) = make_noise_pair_for_test();
        let (sid1, ip1) = add_one(&sessions, "127.0.0.1:2001".parse().unwrap(), s1);
        let (sid2, ip2) = add_one(&sessions, "127.0.0.1:2002".parse().unwrap(), s2);

        // Mark sid1 as ancient (last_seen = process epoch).
        sessions
            .get_by_sid(&sid1)
            .unwrap()
            .last_seen
            .store(0, Ordering::Relaxed);
        // Mark sid2 as unreachably fresh — cannot expire regardless of `now`.
        sessions
            .get_by_sid(&sid2)
            .unwrap()
            .last_seen
            .store(u64::MAX, Ordering::Relaxed);

        // Wait until sec_since_start() > 0 so the expiry condition fires for sid1.
        while sec_since_start() == 0 {
            std::thread::sleep(Duration::from_millis(100));
        }

        // TTL = 0 → expired when `now - last_seen > 0`.
        // sid1: now - 0 = now > 0 ✓ (removed)
        // sid2: now.saturating_sub(u64::MAX) = 0 > 0 ✗ (kept)
        sessions.cleanup_sessions(Duration::ZERO);

        assert!(
            !sessions.is_sid_allocated(sid1),
            "expired session must be removed"
        );
        assert!(
            !sessions.is_holy_ip_allocated(&ip1),
            "expired ip must be released"
        );
        assert!(
            sessions.is_sid_allocated(sid2),
            "fresh session must be kept"
        );
        assert!(sessions.is_holy_ip_allocated(&ip2), "fresh ip must be kept");
    }

    #[test]
    fn test_cleanup_with_large_ttl_keeps_all() {
        let sessions = make_sessions();
        let (s1, _) = make_noise_pair_for_test();
        let (sid, ip) = add_one(&sessions, "127.0.0.1:3000".parse().unwrap(), s1);

        sessions.cleanup_sessions(Duration::from_secs(86400));

        assert!(sessions.is_sid_allocated(sid));
        assert!(sessions.is_holy_ip_allocated(&ip));
    }

    // ── update_sock_addr ───────────────────────────────────────────────────────

    #[test]
    fn test_initial_v4_sock_addr() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let (sid, _) = add_one(&sessions, addr, state);
        assert_eq!(sessions.get_by_sid(&sid).unwrap().sock_addr(), addr);
    }

    #[test]
    fn test_initial_v6_sock_addr() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let (sid, _) = add_one(&sessions, addr, state);
        assert_eq!(sessions.get_by_sid(&sid).unwrap().sock_addr(), addr);
    }

    #[test]
    fn test_update_sock_addr_v4_to_v6() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let v4: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let v6: SocketAddr = "[::1]:9090".parse().unwrap();
        let (sid, _) = add_one(&sessions, v4, state);

        sessions.update_sock_addr(sid, v6);
        assert_eq!(sessions.get_by_sid(&sid).unwrap().sock_addr(), v6);
    }

    #[test]
    fn test_update_sock_addr_v6_to_v4() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let v6: SocketAddr = "[::1]:9090".parse().unwrap();
        let v4: SocketAddr = "172.16.0.1:5555".parse().unwrap();
        let (sid, _) = add_one(&sessions, v6, state);

        sessions.update_sock_addr(sid, v4);
        assert_eq!(sessions.get_by_sid(&sid).unwrap().sock_addr(), v4);
    }

    #[test]
    fn test_update_sock_addr_v4_to_v4() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let v4a: SocketAddr = "192.168.0.1:100".parse().unwrap();
        let v4b: SocketAddr = "10.10.10.10:200".parse().unwrap();
        let (sid, _) = add_one(&sessions, v4a, state);

        sessions.update_sock_addr(sid, v4b);
        assert_eq!(sessions.get_by_sid(&sid).unwrap().sock_addr(), v4b);
    }

    #[test]
    fn test_update_sock_addr_v6_to_v6() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let v6a: SocketAddr = "[::1]:1".parse().unwrap();
        let v6b: SocketAddr = "[2001:db8::ff]:2".parse().unwrap();
        let (sid, _) = add_one(&sessions, v6a, state);

        sessions.update_sock_addr(sid, v6b);
        assert_eq!(sessions.get_by_sid(&sid).unwrap().sock_addr(), v6b);
    }

    // ── get_and_touch ──────────────────────────────────────────────────────────

    #[test]
    fn test_get_and_touch_updates_last_seen() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let (sid, _) = add_one(&sessions, "127.0.0.1:4321".parse().unwrap(), state);

        sessions
            .get_by_sid(&sid)
            .unwrap()
            .last_seen
            .store(0, Ordering::Relaxed);
        let session = sessions.get_and_touch(&sid).unwrap();
        assert!(
            session.last_seen.load(Ordering::Relaxed) >= sec_since_start(),
            "get_and_touch must update last_seen"
        );
    }

    #[test]
    fn test_get_and_touch_unknown_sid_returns_none() {
        let sessions = make_sessions();
        assert!(sessions.get_and_touch(&0xDEAD_BEEF).is_none());
    }

    // ── set_sock_addr ──────────────────────────────────────────────────────────

    #[test]
    fn test_set_sock_addr_direct_v4() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let v4a: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let v4b: SocketAddr = "5.6.7.8:2000".parse().unwrap();
        let (sid, _) = add_one(&sessions, v4a, state);

        let session = sessions.get_by_sid(&sid).unwrap();
        session.set_sock_addr(v4b);
        assert_eq!(session.sock_addr(), v4b);
    }

    // ── touch ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_touch_updates_last_seen() {
        let sessions = make_sessions();
        let (state, _) = make_noise_pair_for_test();
        let (sid, _) = add_one(&sessions, "127.0.0.1:9999".parse().unwrap(), state);

        // Force last_seen to 0 then touch — must become non-zero (current time).
        sessions
            .get_by_sid(&sid)
            .unwrap()
            .last_seen
            .store(0, Ordering::Relaxed);
        sessions.touch(sid);
        let seen = sessions
            .get_by_sid(&sid)
            .unwrap()
            .last_seen
            .load(Ordering::Relaxed);
        assert!(seen >= sec_since_start(), "touch must set last_seen to now");
    }
}
