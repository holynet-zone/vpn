pub mod session;
mod worker;
pub mod error;
mod tun;

use std::{
    net::{IpAddr, SocketAddr},
    thread
};
use std::sync::Arc;
use dashmap::DashMap;
use self::{
    error::RuntimeError,
    session::{ Sessions}
};

use tokio::runtime::Builder;
use tokio::sync::{broadcast};
use crate::config::Config;
use shared::keys::handshake::{PublicKey, SecretKey};
use crate::runtime::tun::set_ipv4_forwarding;
use crate::storage::Client;

pub struct Runtime {
    sock: SocketAddr,
    sk: SecretKey,
    workers: usize,
    // Client pub key -> pre-shared key
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sessions: Sessions,
    session_ttl: usize, // in seconds
    sender_buf_size: usize,
    // tun
    tun_name: String,
    tun_mtu: u16,
    tun_ip: IpAddr,
    tun_prefix: u8,
    // stop signal
    pub stop_tx: broadcast::Sender<RuntimeError>,
}

impl Runtime {

    pub fn from_config(config: Config) -> Result<Self, RuntimeError> {
        let (stop_tx, _) = broadcast::channel::<RuntimeError>(5);

        Ok(Self {
            sock: SocketAddr::new(
                config.general.host.parse().map_err(
                    |err| RuntimeError::Unexpected(format!("invalid host: {}", err))
                )?,
                config.general.port
            ),
            sk: config.general.secret_key,
            workers: if config.runtime.workers == 0 {
                thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
            } else {
                config.runtime.workers
            },
            known_clients: Default::default(), // todo
            sessions: Sessions::new(&config.interface.address, config.interface.prefix),
            session_ttl: 0, // inf
            sender_buf_size: config.runtime.sender_buf_size,
            tun_name: config.interface.name,
            tun_mtu: config.interface.mtu,
            tun_ip: config.interface.address,
            tun_prefix: config.interface.prefix,
            stop_tx,
        })
    }
    
    pub fn insert_clients(&mut self, clients: Vec<Client>) {
        self.known_clients = Arc::new(DashMap::from_iter(
            clients.into_iter()
                .map(|client| (client.peer_pk, client.psk))
        ));
    }
    
    pub async fn run(&mut self) -> Result<(), RuntimeError> {
        tracing::info!(
            "Runtime running on udp://{} with {} workers",
            self.sock,
            self.workers
        );
        
        set_ipv4_forwarding(true)?;
        
        let tun = Arc::new(tun::setup_tun(
            &self.tun_name,
            &self.tun_mtu,
            &self.tun_ip,
            &self.tun_prefix
        ).await?);

        let mut handles = Vec::new();
        
        for worker_id in 1..self.workers + 1 {
            let addr = self.sock;
            let stop_tx = self.stop_tx.clone();
            let sessions = self.sessions.clone();
            let sk = self.sk.clone();
            let known_clients = self.known_clients.clone();
            let tun = tun.clone();
            
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
                    tun,
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
        
        let mut errors = Vec::new();
        for handle in handles {
            if let Err(err) = handle.join().unwrap_or_else(|e| {
                tracing::error!("panic in worker thread: {:?}", e);
                Err(anyhow::anyhow!("panic in worker thread: {:?}", e))
            }) {
                errors.push(RuntimeError::Unexpected(err.to_string()));
            }
        }

        set_ipv4_forwarding(false)?; // todo save bef aft state

        if !errors.is_empty() {
            return Err(RuntimeError::Unexpected(
                format!("{} workers critical failed: {:?}", errors.len(), errors)
            ))
        }
        
        let mut stop_rx = self.stop_tx.subscribe();

        if let Ok(err) = stop_rx.recv().await {
            return Err(err);
        }

        panic!("all workers stopped unexpectedly");
    }
}