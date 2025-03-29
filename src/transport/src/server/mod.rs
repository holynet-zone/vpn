mod request;
mod response;
mod session;
mod worker;
mod error;
pub(crate) mod packet;
mod sender;

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    thread
};
use std::sync::Arc;
use dashmap::DashMap;
use self::{
    request::Request,
    error::RuntimeError,
    response::Response,
    session::{Session, Sessions}
};

use tokio::runtime::Builder;
use tokio::sync::{broadcast, mpsc};
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::server;
use crate::server::sender::ServerSender;
use crate::session::SessionId;

pub struct Server {
    sock: SocketAddr,
    sk: SecretKey,
    workers: usize,
    // Client pub key -> pre-shared key
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sessions: Sessions,
    session_ttl: u64, // in seconds
    sender: sender::ServerSender,
    sender_buffer_size: usize,
    on_session_created: Option<Arc<dyn Fn(SessionId, Sessions) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>,
    on_session_destroyed: Option<Arc<dyn Fn(SessionId, Session) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>,
    on_request: Option<Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>>,
}

impl Server {
    pub fn new(addr: IpAddr, port: u16, sk: SecretKey) -> Self {
        Self {
            sock: SocketAddr::new(addr, port),
            sk,
            workers: thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            known_clients: Default::default(),
            on_session_created: None,
            on_session_destroyed: None,
            on_request: None,
            sessions: Sessions::new(),
            session_ttl: 0, // inf
            sender: ServerSender::default(),
            sender_buffer_size: 1000
        }
    }

    pub fn workers(&mut self, count: usize) -> &mut Self {
        self.workers = count;
        self
    }

    pub fn handle<F, Fut>(&mut self, handler: F) -> &mut Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        self.on_request = Some(Arc::new(move |data| Box::pin(handler(data))));
        self
    }

    pub fn session_ttl(&mut self, ttl: u64) -> &mut Self {
        self.session_ttl = ttl;
        self
    }
    pub fn sessions(&self) -> Sessions{
        self.sessions.clone()
    }

    pub fn sender_buffer_size(&mut self, size: usize) -> &mut Self {
        self.sender_buffer_size = size;
        self
    }

    pub fn sender(&self) -> ServerSender {
        self.sender.clone()
    }
    
    /// Insert a client's public key and pre-shared key
    pub fn insert_client(&mut self, client_pub_key: PublicKey, client_secret_key: SecretKey) -> &mut Self {
        self.known_clients.insert(client_pub_key, client_secret_key);
        self
    }
    
    /// Insert multiple clients at once
    /// 
    /// # Arguments
    /// 
    /// * `clients` - A vector of tuples containing the client's public key and pre-shared key
    pub fn insert_clients(&mut self, clients: Vec<(PublicKey, SecretKey)>) -> &mut Self {
        for (pub_key, secret_key) in clients {
            self.known_clients.insert(pub_key, secret_key);
        }
        self
    }

    pub async fn run(&mut self) -> Result<(), RuntimeError> {
        tracing::info!(
            "Server running on udp://{} with {} workers",
            self.sock,
            self.workers
        );

        let (stop_tx, mut stop_rx) = broadcast::channel::<RuntimeError>(1);
        let mut handles = Vec::new();

        // Senders for server streams
        let mut senders = Vec::new();


        for worker_id in 0..self.workers {
            let addr = self.sock;
            let stop_tx = stop_tx.clone();
            let sessions = self.sessions.clone();
            let sk = self.sk.clone();
            let known_clients = self.known_clients.clone();
            let on_request = self.on_request.clone();
            
            // Sender for worker streams
            let (sender_tx, sender_rx) = mpsc::channel::<(SessionId, server::Response)>(self.sender_buffer_size);
            senders.push(sender_tx);
            
            let handle = thread::spawn(move || {
                let rt = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to create Tokio runtime");
                
                tracing::debug!("worker {} started", worker_id);

                if let Err(err) = rt.block_on(worker::create(
                    addr, 
                    stop_tx,
                    sessions, 
                    known_clients,
                    sk,
                    on_request,
                    sender_rx,
                    worker_id
                )) {
                    tracing::error!("worker {worker_id} failed: {err}");
                    return Err(err);
                }
                
                tracing::debug!("worker {} stopped", worker_id);

                Ok(())
            });

            handles.push(handle);
        }
        
        self.sender.senders = Arc::new(senders);

        let mut errors = Vec::new();
        for handle in handles {
            if let Err(err) = handle.join().unwrap_or_else(|e| {
                tracing::error!("panic in worker thread: {:?}", e);
                Err(anyhow::anyhow!("panic in worker thread: {:?}", e))
            }) {
                errors.push(RuntimeError::UnexpectedError(err.to_string()));
            }
        }

        if !errors.is_empty() {
            return Err(RuntimeError::UnexpectedError(
                format!("{} workers critical failed: {:?}", errors.len(), errors)
            ))
        }

        if let Ok(err) = stop_rx.try_recv() {
            return Err(err);
        }

        panic!("all workers stopped unexpectedly");
    }
}