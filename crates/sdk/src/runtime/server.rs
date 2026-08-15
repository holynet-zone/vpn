mod handshake;
mod network;
mod recv;
mod recv_pool;
pub mod session;

use std::{net::IpAddr, sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::info;

use self::session::Sessions;
use self::{handshake::handshake_executor, network::encrypt_forward, recv::recv_decrypt_forward};
use crate::crypto::{PublicKey, SecretKey};
use crate::gateway::network::Network;
use crate::gateway::transport::Transport;
use crate::runtime::error::{BuildError, RuntimeError};

pub struct ServerBuilder<T: Transport + 'static, N: Network + 'static> {
    transports: Vec<Arc<T>>,
    network: Arc<N>,
    sk: Option<SecretKey>,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    ip: Option<IpAddr>,
    prefix: u8,
    session_timeout: Option<Duration>,
    session_cleanup_interval: Duration,
    handshake_buf: usize,
    decrypt_workers: usize,
}

impl<T: Transport + 'static, N: Network + 'static> ServerBuilder<T, N> {
    pub fn new(transports: Vec<T>, network: N) -> Self {
        Self {
            transports: transports.into_iter().map(Arc::new).collect(),
            network: Arc::new(network),
            sk: None,
            known_clients: Arc::new(DashMap::new()),
            ip: None,
            prefix: 24,
            session_timeout: Some(Duration::from_secs(60 * 5)),
            session_cleanup_interval: Duration::from_secs(60),
            handshake_buf: 1000,
            decrypt_workers: 0,
        }
    }

    pub fn secret_key(mut self, sk: SecretKey) -> Self {
        self.sk = Some(sk);
        self
    }

    pub fn known_clients(mut self, clients: Vec<(PublicKey, SecretKey)>) -> Self {
        self.known_clients = Arc::new(DashMap::from_iter(clients));
        self
    }

    /// Set the VPN server IP and subnet prefix used for client session assignment.
    pub fn ip(mut self, ip: IpAddr, prefix: u8) -> Self {
        self.ip = Some(ip);
        self.prefix = prefix;
        self
    }

    /// Set session inactivity timeout. `None` disables cleanup.
    pub fn session_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.session_timeout = timeout;
        self
    }

    pub fn session_cleanup_interval(mut self, interval: Duration) -> Self {
        self.session_cleanup_interval = interval;
        self
    }

    pub fn handshake_buf(mut self, size: usize) -> Self {
        self.handshake_buf = size;
        self
    }

    /// Number of parallel decrypt workers **per receive socket**.
    ///
    /// `0` or `1` keeps the single-task receive path (one core per flow). `>= 2`
    /// switches to the WireGuard-style pool that spreads one flow's decryption
    /// across that many cores with in-order TUN writes. Pair a large value with
    /// a small reuseport `workers` count when a single bulk flow dominates.
    pub fn decrypt_workers(mut self, count: usize) -> Self {
        self.decrypt_workers = count;
        self
    }

    pub fn build(self) -> Result<Server<T, N>, BuildError> {
        Ok(Server {
            transports: if self.transports.is_empty() {
                return Err(BuildError::MissingRequiredField(
                    "at least one transport is required",
                ));
            } else {
                self.transports
            },
            network: self.network,
            sk: self
                .sk
                .ok_or(BuildError::MissingRequiredField("secret_key"))?,
            known_clients: self.known_clients,
            ip: self.ip.ok_or(BuildError::MissingRequiredField("ip"))?,
            prefix: self.prefix,
            session_timeout: self.session_timeout,
            session_cleanup_interval: self.session_cleanup_interval,
            handshake_buf: self.handshake_buf,
            decrypt_workers: self.decrypt_workers,
        })
    }
}

pub struct Server<T: Transport + 'static, N: Network + 'static> {
    transports: Vec<Arc<T>>,
    network: Arc<N>,
    sk: SecretKey,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    ip: IpAddr,
    prefix: u8,
    session_timeout: Option<Duration>,
    session_cleanup_interval: Duration,
    handshake_buf: usize,
    decrypt_workers: usize,
}

impl<T: Transport + 'static, N: Network + 'static> Server<T, N> {
    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        let sessions = Sessions::new(&self.ip, self.prefix);
        let (_stop_tx, stop_rx) = watch::channel::<bool>(false);

        let mut set: JoinSet<()> = JoinSet::new();

        for transport in self.transports {
            let network = self.network.clone();
            let (handshake_tx, handshake_rx) = tokio::sync::mpsc::channel(self.handshake_buf);
            let inf_timeout = self.session_timeout.is_none();

            // Hot path 1: UDP → decrypt → network (+ inline keepalive responses).
            // With >= 2 decrypt workers, spread one flow's decryption across
            // cores via the WireGuard-style pool; otherwise keep the single-task
            // path (one core per flow).
            if self.decrypt_workers >= 2 {
                set.spawn(recv_pool::recv_decrypt_forward_pool(
                    stop_rx.clone(),
                    transport.clone(),
                    network.clone(),
                    sessions.clone(),
                    handshake_tx,
                    inf_timeout,
                    self.decrypt_workers,
                ));
            } else {
                set.spawn(recv_decrypt_forward(
                    stop_rx.clone(),
                    transport.clone(),
                    network.clone(),
                    sessions.clone(),
                    handshake_tx,
                    inf_timeout,
                ));
            }

            // Hot path 2: network → encrypt → UDP
            set.spawn(encrypt_forward(
                stop_rx.clone(),
                network,
                transport.clone(),
                sessions.clone(),
            ));

            // Rare path: handshake completion
            set.spawn(handshake_executor(
                stop_rx.clone(),
                handshake_rx,
                transport,
                self.known_clients.clone(),
                sessions.clone(),
                self.sk.clone(),
            ));
        }

        if let Some(timeout) = self.session_timeout {
            info!("session cleanup worker started (timeout: {:?})", timeout);
            set.spawn(session::worker::run(
                stop_rx.clone(),
                sessions.clone(),
                timeout,
                self.session_cleanup_interval,
            ));
        } else {
            info!("session cleanup disabled");
        }

        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                tracing::error!("worker panicked: {}", e);
            }
        }

        Err(RuntimeError::Unexpected(
            "all workers exited unexpectedly".into(),
        ))
    }
}
