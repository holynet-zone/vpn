use std::{
    net::SocketAddr,
    time::Instant,
    sync::Arc
};
use tokio::sync::Mutex;
use async_trait::async_trait;
use gen::SessionIdGenerator;
use crate::{

    session::{
        SessionId,
        Alg
    }
};

mod gen;

use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use snow::StatelessTransportState;
use crate::keys::session::SessionKey;

#[derive(Clone)]
pub struct Session {
    pub sock_addr: SocketAddr,
    pub last_seen: Instant,
    pub created_at: Instant,
    pub enc: Alg,
    pub state: Option<Arc<StatelessTransportState>>,
}

#[derive(Clone)]
pub struct Sessions {
    gen: Arc<Mutex<SessionIdGenerator>>,
    map: Arc<DashMap<SessionId, Session>>
}

impl Sessions {
    pub fn new() -> Self {
        Sessions {
            gen: Arc::new(Mutex::new(SessionIdGenerator::new(1))),
            map: Arc::new(DashMap::new())
        }
    }

    pub async fn add(&self, sock_addr: SocketAddr, enc: Alg, state: Option<StatelessTransportState>) -> Option<SessionId> {
        let session_id = self.gen.lock().await.next()?;
        let time = Instant::now();
        self.map.insert(session_id, Session {
            sock_addr,
            last_seen: time,
            created_at: time,
            enc,
            state: state.map(|s| Arc::new(s))
        });
        Some(session_id)
    }
    
    pub fn set_transport_state(&self, sid: &SessionId, state: StatelessTransportState) {
        self.map.get_mut(sid).map(|mut session| {
            session.state = Some(Arc::new(state));
        });
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

    // pub async fn set_kv(&self, sid: SessionId, key: String, value: String) {
    //     match self.map.read().await.get(&sid) {
    //         Some(sessions_guard) => {
    //             sessions_guard.write().await.store.insert(key, value);
    //         },
    //         None => tracing::debug!("Session::set session with id {} not found", sid)
    //     }
    // }
    // 
    // pub async fn get_kv(&self, sid: SessionId, key: String) -> Option<String> {
    //     match self.map.read().await.get(&sid) {
    //         Some(sessions_guard) => sessions_guard.read().await.store.get(&key).cloned(),
    //         None => {
    //             tracing::debug!("Session::get session with id {} not found", sid);
    //             None
    //         }
    //     }
    // }
    
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
        context.map.remove(self);
        context.gen.lock().await.release(self);
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
trait GetSession {
    fn get(&self, context: &Sessions) -> Option<Session>;
}



impl GetSession for &SessionId {
    fn get(&self, context: &Sessions) -> Option<Session> {
        if let Some(session_lock) = context.map.get(self.clone()) { // TODO: clone
            Some(session_lock.clone())
        } else {
            None
        }
    }
}
