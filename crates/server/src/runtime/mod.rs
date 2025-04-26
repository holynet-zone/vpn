pub mod session;
mod worker;
pub mod error;

use std::{
    net::{IpAddr, SocketAddr},
    thread
};
use std::sync::Arc;
use std::time::Duration;
use dashmap::DashMap;
use self::{
    error::RuntimeError,
    session::{ Sessions}
};

use tokio::runtime::Builder;
use tokio::sync::{broadcast};
use crate::config::{Config, RuntimeConfig};
use shared::{
    keys::handshake::{PublicKey, SecretKey},
    network::set_ipv4_forwarding
};
use shared::tun::setup_tun;

pub struct Runtime {
    sock: SocketAddr,
    sk: SecretKey,
    // Client pub key -> pre-shared key
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sessions: Sessions,
    config: RuntimeConfig,
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
        let (stop_tx, _) = broadcast::channel::<RuntimeError>(8);

        Ok(Self {
            sock: SocketAddr::new(
                config.general.host.parse().map_err(
                    |err| RuntimeError::Unexpected(format!("invalid host: {}", err))
                )?,
                config.general.port
            ),
            sk: config.general.secret_key,
            config: config.runtime.unwrap_or_default(),
            known_clients: Default::default(), // todo
            sessions: Sessions::new(&config.interface.address, config.interface.prefix),
            tun_name: config.interface.name,
            tun_mtu: config.interface.mtu,
            tun_ip: config.interface.address,
            tun_prefix: config.interface.prefix,
            stop_tx,
        })
    }

    pub fn insert_clients(&mut self, clients: Vec<(PublicKey, SecretKey)>) {
        self.known_clients = Arc::new(DashMap::from_iter(clients));
    }

    pub async fn run(&mut self) -> Result<(), Vec<RuntimeError>> {
        let workers = match self.config.workers == 0 {
            true => thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            false => self.config.workers
        };

        tracing::info!(
        "Runtime running on udp://{} with {} workers",
        self.sock,
        workers
    );

        set_ipv4_forwarding(true).map_err(|err| vec![RuntimeError::from(err)])?;

        let tun = setup_tun(
            &self.tun_name,
            self.tun_mtu,
            self.tun_ip,
            self.tun_prefix,
            true
        ).await.map_err(|err| vec![RuntimeError::from(err)])?;
        
        let rt = Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");

        let mut handles = Vec::new();

        for worker_id in 1..workers + 1 {
            let addr = self.sock;
            let stop_tx = self.stop_tx.clone();
            let sessions = self.sessions.clone();
            let sk = self.sk.clone();
            let known_clients = self.known_clients.clone();
            let tun = tun.try_clone().map_err(|err| vec![RuntimeError::Tun(
                format!("failed to clone tun device: {}", err)
            )])?;
            let config = self.config.clone();

            let handle = rt.spawn(async move {
                tracing::debug!("worker {} started", worker_id);

                if let Err(err) = worker::create(
                    addr,
                    stop_tx,
                    sessions,
                    known_clients,
                    sk,
                    tun,
                    worker_id,
                    config
                ).await {
                    tracing::error!("worker {worker_id} failed: {err}");
                    return Err(err);
                }

                tracing::debug!("worker {} stopped", worker_id);
                Ok(())
            });

            handles.push(handle);
        }

        // session cleanup
        let session = self.config.session.clone().unwrap_or_default();
        if session.timeout != 0 {
            tracing::info!("session cleanup worker started");
            tokio::spawn(session::worker::run(
                self.stop_tx.clone(),
                self.sessions.clone(),
                Duration::from_secs(session.timeout as u64),
                Duration::from_secs(session.cleanup_interval as u64),
            ));
        } else {
            tracing::info!("session cleanup worker disabled");
        }

        let mut errors = Vec::new();
        for handle in handles {
            if let Err(err) = handle.await.unwrap() {
                errors.push(RuntimeError::Unexpected(format!("{:?}", err)));
            }
        }

        set_ipv4_forwarding(false).map_err(|err| vec![RuntimeError::from(err)])?;

        if !errors.is_empty() {
            return Err(errors);
        }

        let mut stop_rx = self.stop_tx.subscribe();

        if let Ok(err) = stop_rx.recv().await {
            return Err(vec![err]);
        }

        panic!("all workers stopped unexpectedly");
    }
}