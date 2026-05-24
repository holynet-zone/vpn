mod handshake;
mod recv;
pub mod session;
mod tun;

use std::{net::IpAddr, sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::info;

use self::session::Sessions;
use self::{handshake::handshake_executor, recv::recv_decrypt_forward, tun::tun_encrypt_forward};
use crate::crypto::{PublicKey, SecretKey};
use crate::gateway::transport::Transport;
use crate::network::set_ipv4_forwarding;
use crate::runtime::error::{BuildError, RuntimeError};
use crate::tun::setup as tun_setup;

pub struct ServerBuilder<T: Transport + 'static> {
    transports: Vec<Arc<T>>,
    sk: Option<SecretKey>,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    // TUN
    tun_name: Option<String>,
    tun_mtu: u16,
    tun_ip: Option<IpAddr>,
    tun_prefix: u8,
    // Session cleanup
    session_timeout: Option<Duration>,
    session_cleanup_interval: Duration,
    // Buffers
    handshake_buf: usize,
}

impl<T: Transport + 'static> ServerBuilder<T> {
    /// Create a builder with the given pool of transports (e.g. from
    /// `UdpTransport::new_pool` for SO_REUSEPORT workers).
    pub fn new(transports: Vec<T>) -> Self {
        Self {
            transports: transports.into_iter().map(Arc::new).collect(),
            sk: None,
            known_clients: Arc::new(DashMap::new()),
            tun_name: None,
            tun_mtu: 1420,
            tun_ip: None,
            tun_prefix: 24,
            session_timeout: Some(Duration::from_secs(60 * 5)),
            session_cleanup_interval: Duration::from_secs(60),
            handshake_buf: 1000,
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

    pub fn tun_name(mut self, name: impl Into<String>) -> Self {
        self.tun_name = Some(name.into());
        self
    }

    pub fn tun_mtu(mut self, mtu: u16) -> Self {
        self.tun_mtu = mtu;
        self
    }

    pub fn tun_ip(mut self, ip: IpAddr, prefix: u8) -> Self {
        self.tun_ip = Some(ip);
        self.tun_prefix = prefix;
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

    pub fn build(self) -> Result<Server<T>, BuildError> {
        Ok(Server {
            transports: if self.transports.is_empty() {
                return Err(BuildError::MissingRequiredField(
                    "at least one transport is required",
                ));
            } else {
                self.transports
            },
            sk: self
                .sk
                .ok_or(BuildError::MissingRequiredField("secret_key"))?,
            known_clients: self.known_clients,
            tun_name: self
                .tun_name
                .ok_or(BuildError::MissingRequiredField("tun_name"))?,
            tun_mtu: self.tun_mtu,
            tun_ip: self
                .tun_ip
                .ok_or(BuildError::MissingRequiredField("tun_ip"))?,
            tun_prefix: self.tun_prefix,
            session_timeout: self.session_timeout,
            session_cleanup_interval: self.session_cleanup_interval,
            handshake_buf: self.handshake_buf,
        })
    }
}

pub struct Server<T: Transport + 'static> {
    transports: Vec<Arc<T>>,
    sk: SecretKey,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    // TUN
    tun_name: String,
    tun_mtu: u16,
    tun_ip: IpAddr,
    tun_prefix: u8,
    // Session cleanup
    session_timeout: Option<Duration>,
    session_cleanup_interval: Duration,
    // Buffers
    handshake_buf: usize,
}

impl<T: Transport + 'static> Server<T> {
    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        set_ipv4_forwarding(true)?;

        let tun = tun_setup(&self.tun_name, self.tun_mtu, true).await?;

        match self.tun_ip {
            IpAddr::V4(addr) => {
                tun.set_network_address(addr, self.tun_prefix, None)
                    .map_err(|e| RuntimeError::IO(format!("set tun network address: {e}")))?;
            }
            IpAddr::V6(addr) => {
                tun.add_address_v6(addr, self.tun_prefix)
                    .map_err(|e| RuntimeError::IO(format!("set tun ipv6 address: {e}")))?;
            }
        }

        let sessions = Sessions::new(&self.tun_ip, self.tun_prefix);
        let tun = Arc::new(tun);
        let (_stop_tx, stop_rx) = watch::channel::<bool>(false);

        let mut set: JoinSet<()> = JoinSet::new();

        for transport in self.transports {
            let tun_clone = tun
                .try_clone()
                .map_err(|e| RuntimeError::IO(format!("clone tun device: {e}")))?;
            let tun_clone = Arc::new(tun_clone);

            let (handshake_tx, handshake_rx) = tokio::sync::mpsc::channel(self.handshake_buf);

            let inf_timeout = self.session_timeout.is_none();

            // Hot path 1: UDP → decrypt → TUN (+ inline keepalive responses)
            set.spawn(recv_decrypt_forward(
                stop_rx.clone(),
                transport.clone(),
                tun_clone.clone(),
                sessions.clone(),
                handshake_tx,
                inf_timeout,
                self.tun_mtu,
            ));

            // Hot path 2: TUN → encrypt → UDP
            set.spawn(tun_encrypt_forward(
                stop_rx.clone(),
                tun_clone,
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

        set_ipv4_forwarding(false)?;

        Err(RuntimeError::Unexpected(
            "all workers exited unexpectedly".into(),
        ))
    }
}
