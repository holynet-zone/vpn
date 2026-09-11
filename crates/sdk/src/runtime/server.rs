mod handshake;
mod network;
mod recv;
mod recv_pool;
pub mod session;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use dashmap::DashMap;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::info;

use self::session::Sessions;
use self::{handshake::handshake_executor, network::encrypt_forward, recv::recv_decrypt_forward};
use crate::crypto::{PublicKey, SecretKey};
use crate::gateway::network::Network;
use crate::gateway::transport::Transport;
use crate::identity::{AccountKey, AccountPublicKey};
use crate::protocol::NodeEntry;
use crate::registry::{NodeRecord, NodeRegistry};
use crate::runtime::error::{BuildError, RuntimeError};

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct ServerBuilder<T: Transport + 'static, N: Network + 'static> {
    transports: Vec<Arc<T>>,
    network: Arc<N>,
    sk: Option<SecretKey>,
    known_accounts: Arc<DashMap<AccountPublicKey, SecretKey>>,
    reservations: Vec<((AccountPublicKey, u32), IpAddr)>,
    advertise_endpoint: Option<SocketAddr>,
    node_label: String,
    peer_nodes: Vec<NodeEntry>,
    authority: Option<AccountKey>,
    peer_records: Vec<NodeRecord>,
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
            known_accounts: Arc::new(DashMap::new()),
            reservations: Vec::new(),
            advertise_endpoint: None,
            node_label: String::new(),
            peer_nodes: Vec::new(),
            authority: None,
            peer_records: Vec::new(),
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

    pub fn known_accounts(mut self, accounts: Vec<(AccountPublicKey, SecretKey)>) -> Self {
        self.known_accounts = Arc::new(DashMap::from_iter(accounts));
        self
    }

    /// Hard-pin `(account, device_index)` to a fixed address. Reserved addresses
    /// are held out of the dynamic pool and only ever assigned to their owner.
    pub fn reservations(mut self, reservations: Vec<((AccountPublicKey, u32), IpAddr)>) -> Self {
        self.reservations = reservations;
        self
    }

    /// Advertise this node in the registry it hands to clients: the reachable
    /// endpoint clients dial and a human label. The node's own subnet and pubkey
    /// are filled from `ip`/`secret_key`.
    pub fn advertise(mut self, endpoint: SocketAddr, label: impl Into<String>) -> Self {
        self.advertise_endpoint = Some(endpoint);
        self.node_label = label.into();
        self
    }

    /// Statically-known peer nodes included in the registry alongside this node.
    /// Used only when no `authority` is set (unsigned single-network mode).
    pub fn peer_nodes(mut self, nodes: Vec<NodeEntry>) -> Self {
        self.peer_nodes = nodes;
        self
    }

    /// Network authority key. When set, the node advertises a *signed*
    /// [`NodeRecord`] and its registry is built by verified CRDT merge, so peer
    /// records can be relayed by untrusted nodes. Without it the node stays in
    /// the unsigned single-network mode (`advertise` / `peer_nodes`).
    pub fn authority(mut self, authority: AccountKey) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Authority-signed peer records merged into the registry (used with
    /// `authority`). Records failing verification are dropped.
    pub fn peer_records(mut self, records: Vec<NodeRecord>) -> Self {
        self.peer_records = records;
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
            known_accounts: self.known_accounts,
            reservations: self.reservations,
            advertise_endpoint: self.advertise_endpoint,
            node_label: self.node_label,
            peer_nodes: self.peer_nodes,
            authority: self.authority,
            peer_records: self.peer_records,
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
    known_accounts: Arc<DashMap<AccountPublicKey, SecretKey>>,
    reservations: Vec<((AccountPublicKey, u32), IpAddr)>,
    advertise_endpoint: Option<SocketAddr>,
    node_label: String,
    peer_nodes: Vec<NodeEntry>,
    authority: Option<AccountKey>,
    peer_records: Vec<NodeRecord>,
    ip: IpAddr,
    prefix: u8,
    session_timeout: Option<Duration>,
    session_cleanup_interval: Duration,
    handshake_buf: usize,
    decrypt_workers: usize,
}

impl<T: Transport + 'static, N: Network + 'static> Server<T, N> {
    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        let self_entry = self.advertise_endpoint.map(|endpoint| NodeEntry {
            node_pk: PublicKey::from_secret(&self.sk),
            endpoint,
            subnet: self.ip,
            prefix: self.prefix,
            label: self.node_label.clone(),
        });
        let nodes = match &self.authority {
            Some(authority) => {
                let mut registry = NodeRegistry::new(authority.public());
                if let Some(entry) = self_entry {
                    registry.merge(NodeRecord::sign(authority, entry, now_millis(), false));
                }
                registry.merge_all(self.peer_records);
                registry.active_entries()
            }
            None => {
                let mut nodes = Vec::new();
                nodes.extend(self_entry);
                nodes.extend(self.peer_nodes.iter().cloned());
                nodes
            }
        };
        let sessions = Sessions::with_config(&self.ip, self.prefix, self.reservations, nodes);
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
                self.known_accounts.clone(),
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
