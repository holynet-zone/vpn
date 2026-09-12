mod gossip;
mod handshake;
mod network;
mod recv;
mod recv_pool;
mod relay;
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
use crate::identity::AccountPublicKey;
use crate::protocol::NodeEntry;
use crate::registry::{NodeRecord, NodeRegistry};
use crate::runtime::error::{BuildError, RuntimeError};

pub struct ServerBuilder<T: Transport + 'static, N: Network + 'static> {
    transports: Vec<Arc<T>>,
    network: Arc<N>,
    sk: Option<SecretKey>,
    known_accounts: Arc<DashMap<AccountPublicKey, SecretKey>>,
    reservations: Vec<((AccountPublicKey, u32), IpAddr)>,
    advertise_endpoint: Option<SocketAddr>,
    node_label: String,
    peer_nodes: Vec<NodeEntry>,
    trusted_authority: Option<AccountPublicKey>,
    node_records: Vec<NodeRecord>,
    gossip_interval: Duration,
    #[allow(clippy::type_complexity)]
    on_registry_merge: Option<Box<dyn Fn(&[NodeRecord]) + Send + Sync>>,
    #[allow(clippy::type_complexity)]
    on_registry_reap: Option<Box<dyn Fn(&[NodeRecord]) + Send + Sync>>,
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
            trusted_authority: None,
            node_records: Vec::new(),
            gossip_interval: Duration::from_secs(30),
            on_registry_merge: None,
            on_registry_reap: None,
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

    /// Trusted network authority public key. When set, the registry is built by
    /// verified CRDT merge of `node_records` (zero-trust relay model): the node
    /// holds no signing key, only verifies. Without it the node stays in the
    /// unsigned single-network mode (`advertise` / `peer_nodes`).
    pub fn trusted_authority(mut self, authority: AccountPublicKey) -> Self {
        self.trusted_authority = Some(authority);
        self
    }

    /// Authority-signed node records (this node's own record plus peers) merged
    /// into the registry. Requires `trusted_authority`; records from another
    /// authority or with a bad signature are dropped.
    pub fn node_records(mut self, records: Vec<NodeRecord>) -> Self {
        self.node_records = records;
        self
    }

    /// Interval between node-to-node registry gossip pushes (signed mode only).
    pub fn gossip_interval(mut self, interval: Duration) -> Self {
        self.gossip_interval = interval;
        self
    }

    /// Sink invoked with records newly applied by a gossip merge, so the host can
    /// persist them (the registry survives restart without waiting a gossip cycle).
    pub fn on_registry_merge(mut self, cb: impl Fn(&[NodeRecord]) + Send + Sync + 'static) -> Self {
        self.on_registry_merge = Some(Box::new(cb));
        self
    }

    /// Sink invoked with tombstones reaped by periodic GC, so the host can drop
    /// them from durable storage in step with the in-memory registry.
    pub fn on_registry_reap(mut self, cb: impl Fn(&[NodeRecord]) + Send + Sync + 'static) -> Self {
        self.on_registry_reap = Some(Box::new(cb));
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
            trusted_authority: self.trusted_authority,
            node_records: self.node_records,
            gossip_interval: self.gossip_interval,
            on_registry_merge: self.on_registry_merge,
            on_registry_reap: self.on_registry_reap,
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
    trusted_authority: Option<AccountPublicKey>,
    node_records: Vec<NodeRecord>,
    gossip_interval: Duration,
    #[allow(clippy::type_complexity)]
    on_registry_merge: Option<Box<dyn Fn(&[NodeRecord]) + Send + Sync>>,
    #[allow(clippy::type_complexity)]
    on_registry_reap: Option<Box<dyn Fn(&[NodeRecord]) + Send + Sync>>,
    ip: IpAddr,
    prefix: u8,
    session_timeout: Option<Duration>,
    session_cleanup_interval: Duration,
    handshake_buf: usize,
    decrypt_workers: usize,
}

impl<T: Transport + 'static, N: Network + 'static> Server<T, N> {
    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        let self_pk = PublicKey::from_secret(&self.sk);
        // Zero-trust relay: the node holds no signing key. It verifies and merges
        // operator-signed records (its own self-record included) into a live
        // registry fed by gossip. Unsigned mode keeps a static advertised list.
        let (nodes, registry) = match self.trusted_authority {
            Some(trusted) => {
                let mut reg = NodeRegistry::new(trusted);
                reg.merge_all(self.node_records);
                (Vec::new(), Some(reg))
            }
            None => {
                let mut nodes = Vec::new();
                if let Some(endpoint) = self.advertise_endpoint {
                    nodes.push(NodeEntry {
                        node_pk: self_pk.clone(),
                        endpoint,
                        subnet: self.ip,
                        prefix: self.prefix,
                        label: self.node_label.clone(),
                    });
                }
                nodes.extend(self.peer_nodes.iter().cloned());
                (nodes, None)
            }
        };
        let gossip_enabled = registry.is_some();
        let sessions =
            Sessions::with_config(&self.ip, self.prefix, self.reservations, nodes, registry);
        if let Some(cb) = self.on_registry_merge {
            sessions.set_merge_callback(cb);
        }
        if let Some(cb) = self.on_registry_reap {
            sessions.set_reap_callback(cb);
        }
        let (_stop_tx, stop_rx) = watch::channel::<bool>(false);

        let mut set: JoinSet<()> = JoinSet::new();

        // Transparent inter-node relay: one shared flow table + an idle reaper.
        let relay_table = Arc::new(relay::RelayTable::new());
        set.spawn(relay::gc_loop(relay_table.clone(), stop_rx.clone()));

        // One gossip pusher for the node, sharing the first receive socket.
        if gossip_enabled && let Some(transport) = self.transports.first().cloned() {
            set.spawn(gossip::gossip_loop(
                stop_rx.clone(),
                transport,
                sessions.clone(),
                self_pk,
                self.gossip_interval,
            ));
        }

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
                    relay_table.clone(),
                ));
            } else {
                set.spawn(recv_decrypt_forward(
                    stop_rx.clone(),
                    transport.clone(),
                    network.clone(),
                    sessions.clone(),
                    handshake_tx,
                    inf_timeout,
                    relay_table.clone(),
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
