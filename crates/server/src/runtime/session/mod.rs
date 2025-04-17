mod generator;

use std::{
    net::SocketAddr,
    time::Instant,
    sync::Arc
};
use std::net::IpAddr;
use tokio::sync::Mutex;
use async_trait::async_trait;
use generator::{
    SessionIdGenerator,
    IpAddressGenerator,
    increment_ip
};


use dashmap::DashMap;
use snow::StatelessTransportState;
use shared::session::{Alg, SessionId};
pub(crate) use crate::runtime::session::generator::HolyIp;

#[derive(Clone)]
pub struct Session {
    pub id: SessionId,
    pub sock_addr: SocketAddr,
    pub last_seen: Instant,
    pub created_at: Instant,
    pub holy_ip: HolyIp,
    pub enc: Alg,
    pub state: Option<Arc<StatelessTransportState>>,
}

#[derive(Clone)]
pub struct Sessions {
    sid_gen: Arc<Mutex<SessionIdGenerator>>,
    holy_ip_gen: Arc<Mutex<IpAddressGenerator>>,
    map: Arc<DashMap<SessionId, Session>>,
    holy_ip_map: Arc<DashMap<HolyIp, SessionId>>,
}

impl Sessions {
    pub fn new(network: &IpAddr, prefix: u8) -> Self {
        Sessions {
            sid_gen: Arc::new(Mutex::new(SessionIdGenerator::new(1))),
            holy_ip_gen: Arc::new(Mutex::new(IpAddressGenerator::new(increment_ip(*network), prefix))),
            map: Arc::new(DashMap::new()),
            holy_ip_map: Arc::new(DashMap::new())
        }
    }

    pub async fn add(&self, sock_addr: SocketAddr, enc: Alg, state: Option<StatelessTransportState>) -> Option<(SessionId, HolyIp)> {
        let session_id = self.sid_gen.lock().await.next()?;
        match self.holy_ip_gen.lock().await.next() {
            Some(ip) => {
                let time = Instant::now();
                self.map.insert(session_id, Session {
                    id: session_id,
                    sock_addr,
                    last_seen: time,
                    created_at: time,
                    holy_ip: ip,
                    enc,
                    state: state.map(Arc::new)
                });
                self.holy_ip_map.insert(ip, session_id);
                Some((session_id, ip))
            },
            None => {
                self.sid_gen.lock().await.release(&session_id);
                None
            }
        }
    }
    
    pub fn set_transport_state(&self, sid: &SessionId, state: StatelessTransportState) {
        if let Some(mut session) = self.map.get_mut(sid) { 
            session.state = Some(Arc::new(state)); 
        }
    }

    pub async fn release<K: ReleaseKey>(&self, key: K) {
        key.release(self).await
    }

    pub async fn is_allocated<K: IsAllocated>(&self, key: K) -> bool {
        key.is_allocated(self).await
    }

    pub async fn get<K: GetSession>(&self, key: K) -> Option<Session> {
        key.get(self)
    }
    
    pub async fn touch(&self, sid: SessionId) {
        match self.map.get_mut(&sid) {
            Some(mut sessions_guard) => {
                sessions_guard.last_seen = Instant::now();
            },
            None => tracing::debug!("Session::touch session with id {} not found", sid)
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
        let holy_ip = context.map.remove(self).map(|(sid, session)|{
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
    fn get(&self, context: &Sessions) -> Option<Session>;
}



impl GetSession for &SessionId {
    fn get(&self, context: &Sessions) -> Option<Session> {
        context.map.get(*self).map(|session_lock| session_lock.clone())
    }
}

impl GetSession for &IpAddr {
    fn get(&self, context: &Sessions) -> Option<Session> {
        if let Some(session_lock) = context.holy_ip_map.get(*self) { // todo clone
            context.map.get(&session_lock.clone()).map(|session| session.clone())
        } else {
            None
        }
    }
}