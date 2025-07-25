pub mod session;
mod worker;
pub mod error;
mod network;
mod transport;

use std::{
    net::{IpAddr, SocketAddr},
    thread
};
use std::sync::Arc;
use std::time::Duration;
use dashmap::DashMap;
use self::{
    error::RuntimeError,
    session::Sessions
};

use tokio::runtime::Builder;
use tokio::sync::{broadcast};
use tracing::info;
use crate::config::{Config, RuntimeConfig};
use shared::{
    keys::handshake::{PublicKey, SecretKey},
    network::set_ipv4_forwarding
};
use shared::tun::setup_tun;
use crate::runtime::transport::Transport;
#[cfg(feature = "udp")]
use crate::runtime::transport::udp::UdpTransport;

#[cfg(feature = "ws")]
use crate::runtime::transport::ws::WsTransport;

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

        set_ipv4_forwarding(true).map_err(|err| vec![RuntimeError::from(err)])?;

        let tun = setup_tun(
            &self.tun_name,
            self.tun_mtu,
            true
        ).await.map_err(|err| vec![RuntimeError::from(err)])?;
        
        match self.tun_ip {
            IpAddr::V4(addr) => {
                tun.set_network_address(addr, self.tun_prefix, None)
                    .map_err(|err| vec![RuntimeError::Tun(
                        format!("failed to set network address: {}", err)
                    )])?;
            }
            IpAddr::V6(addr) => {
                tun.add_address_v6(addr, self.tun_prefix)
                    .map_err(|err| vec![RuntimeError::Tun(
                        format!("failed to set network address: {}", err)
                    )])?;
            }
        }

        let mut transports: Vec<Arc<dyn Transport>> = match () {
            #[cfg(feature = "udp")]
            _ if cfg!(feature = "udp") => {
                UdpTransport::new_pool(
                    self.sock,
                    self.config.so_rcvbuf,
                    self.config.so_sndbuf,
                    workers
                ).map_err(|err| vec![err])?
                    .into_iter()
                    .map(|t| Arc::new(t) as Arc<dyn Transport>)
                    .collect()
            }
            #[cfg(feature = "ws")]
            _ if cfg!(feature = "ws") => {
                WsTransport::new_pool(
                    self.sock,
                    self.config.so_rcvbuf,
                    self.config.so_sndbuf,
                    workers
                ).map_err(|err| vec![err])?
                    .into_iter()
                    .map(|t| Arc::new(t) as Arc<dyn Transport>)
                    .collect()
            }
            _ => unreachable!("transport is not selected, please enable one of transport features")
        };
        
        let rt = Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");

        let mut handles = Vec::new();

        for worker_id in 1..workers + 1 {
            let stop_tx = self.stop_tx.clone();
            let sessions = self.sessions.clone();
            let sk = self.sk.clone();
            let known_clients = self.known_clients.clone();
            let tun = tun.try_clone().map_err(|err| vec![RuntimeError::Tun(
                format!("failed to clone tun device: {}", err)
            )])?;
            let transport = transports.pop().unwrap(); // unwrap is safe here
            let config = self.config.clone();

            let handle = rt.spawn(async move {
                tracing::debug!("worker {} started", worker_id);

                if let Err(err) = worker::create(
                    transport,
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
            info!("session cleanup worker started");
            tokio::spawn(session::worker::run(
                self.stop_tx.clone(),
                self.sessions.clone(),
                Duration::from_secs(session.timeout as u64),
                Duration::from_secs(session.cleanup_interval as u64),
            ));
        } else {
            info!("session cleanup worker disabled");
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
