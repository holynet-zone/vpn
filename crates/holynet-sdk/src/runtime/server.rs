mod data;
mod handshake;
pub mod session;
mod transport;
mod network;

use std::{
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use dashmap::DashMap;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tracing::info;


use crate::crypto::{PublicKey, SecretKey};
use crate::gateway::transport::Transport;
use crate::network::set_ipv4_forwarding;
use crate::runtime::error::{BuildError, RuntimeError};
use crate::tun::setup_tun;
use self::session::{Sessions, HolyIp};
use self::{
    data::{data_transport_executor, data_tun_executor},
    handshake::handshake_executor,
    network::{tun_listener, tun_sender},
    transport::{transport_listener, transport_sender},
};

pub struct ServerBuilder {
    transports: Vec<Arc<dyn Transport>>,
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
    out_transport_buf: usize,
    out_tun_buf: usize,
    handshake_buf: usize,
    data_transport_buf: usize,
    data_tun_buf: usize,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
            sk: None,
            known_clients: Arc::new(DashMap::new()),
            tun_name: None,
            tun_mtu: 1420,
            tun_ip: None,
            tun_prefix: 24,
            session_timeout: Some(Duration::from_secs(60 * 5)),
            session_cleanup_interval: Duration::from_secs(60),
            out_transport_buf: 1000,
            out_tun_buf: 1000,
            handshake_buf: 1000,
            data_transport_buf: 1000,
            data_tun_buf: 1000,
        }
    }

    /// Add a transport. Call multiple times for multiple workers.
    pub fn transport<T: Transport + 'static>(mut self, transport: T) -> Self {
        self.transports.push(Arc::new(transport));
        self
    }

    pub fn transports(mut self, transports: Vec<Arc<dyn Transport>>) -> Self {
        self.transports = transports;
        self
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

    pub fn out_transport_buf(mut self, size: usize) -> Self {
        self.out_transport_buf = size;
        self
    }

    pub fn out_tun_buf(mut self, size: usize) -> Self {
        self.out_tun_buf = size;
        self
    }

    pub fn handshake_buf(mut self, size: usize) -> Self {
        self.handshake_buf = size;
        self
    }

    pub fn data_transport_buf(mut self, size: usize) -> Self {
        self.data_transport_buf = size;
        self
    }

    pub fn data_tun_buf(mut self, size: usize) -> Self {
        self.data_tun_buf = size;
        self
    }

    pub fn build(self) -> Result<Server, BuildError> {
        Ok(Server {
            transports: if self.transports.is_empty() {
                return Err(BuildError::MissingRequiredField("at least one transport is required"));
            } else {
                self.transports
            },
            sk: self.sk.ok_or(BuildError::MissingRequiredField("secret_key"))?,
            known_clients: self.known_clients,
            tun_name: self.tun_name.ok_or(BuildError::MissingRequiredField("tun_name"))?,
            tun_mtu: self.tun_mtu,
            tun_ip: self.tun_ip.ok_or(BuildError::MissingRequiredField("tun_ip"))?,
            tun_prefix: self.tun_prefix,
            session_timeout: self.session_timeout,
            session_cleanup_interval: self.session_cleanup_interval,
            out_transport_buf: self.out_transport_buf,
            out_tun_buf: self.out_tun_buf,
            handshake_buf: self.handshake_buf,
            data_transport_buf: self.data_transport_buf,
            data_tun_buf: self.data_tun_buf,
        })
    }
}

pub struct Server {
    transports: Vec<Arc<dyn Transport>>,
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
    out_transport_buf: usize,
    out_tun_buf: usize,
    handshake_buf: usize,
    data_transport_buf: usize,
    data_tun_buf: usize,
}

impl Server {
    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        set_ipv4_forwarding(true)?;

        let tun = setup_tun(&self.tun_name, self.tun_mtu, true).await?;

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
        let (stop_tx, _) = broadcast::channel::<RuntimeError>(8);

        let mut set: JoinSet<()> = JoinSet::new();

        for transport in self.transports {
            let tun = tun.try_clone()
                .map_err(|e| RuntimeError::IO(format!("clone tun device: {e}")))?;
            let tun = Arc::new(tun);

            let (out_transport_tx, out_transport_rx) =
                tokio::sync::mpsc::channel(self.out_transport_buf);
            let (out_tun_tx, out_tun_rx) =
                tokio::sync::mpsc::channel(self.out_tun_buf);
            let (handshake_tx, handshake_rx) =
                tokio::sync::mpsc::channel(self.handshake_buf);
            let (data_transport_tx, data_transport_rx) =
                tokio::sync::mpsc::channel(self.data_transport_buf);
            let (data_tun_tx, data_tun_rx) =
                tokio::sync::mpsc::channel::<(Vec<u8>, HolyIp)>(self.data_tun_buf);

            let inf_timeout = self.session_timeout.is_none();

            set.spawn(transport_listener(
                stop_tx.subscribe(),
                transport.clone(),
                handshake_tx,
                data_transport_tx,
            ));
            set.spawn(transport_sender(
                stop_tx.subscribe(),
                transport.clone(),
                out_transport_rx,
            ));
            set.spawn(tun_listener(
                stop_tx.subscribe(),
                tun.clone(),
                data_tun_tx,
            ));
            set.spawn(tun_sender(
                stop_tx.subscribe(),
                tun.clone(),
                out_tun_rx,
            ));
            set.spawn(handshake_executor(
                stop_tx.subscribe(),
                handshake_rx,
                out_transport_tx.clone(),
                self.known_clients.clone(),
                sessions.clone(),
                self.sk.clone(),
            ));
            set.spawn(data_transport_executor(
                stop_tx.subscribe(),
                data_transport_rx,
                out_transport_tx.clone(),
                out_tun_tx.clone(),
                sessions.clone(),
                inf_timeout,
            ));
            set.spawn(data_tun_executor(
                stop_tx.subscribe(),
                data_tun_rx,
                out_transport_tx,
                sessions.clone(),
            ));
        }

        if let Some(timeout) = self.session_timeout {
            info!("session cleanup worker started (timeout: {:?})", timeout);
            set.spawn(session::worker::run(
                stop_tx.clone(),
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

        Err(RuntimeError::Unexpected("all workers exited unexpectedly".into()))
    }
}
