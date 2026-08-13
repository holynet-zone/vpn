mod connector;
mod keepalive;
mod network;
mod network_pool;
mod recv;

use std::{sync::Arc, time::Duration};

use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::{
    gateway::{network::Network, transport::ClientTransport},
    protocol::Alg,
    runtime::{
        client::{
            keepalive::keepalive_sender, network::encrypt_forward, recv::recv_decrypt_forward,
        },
        cred::Cred,
        error::{BuildError, RuntimeError},
        state::RuntimeState,
    },
};

pub(super) const AWAIT_STATE_DELAY: Duration = Duration::from_secs(1);
pub(super) const MAX_PACKET_SIZE: usize = 65536;

pub struct ClientBuilder<T: ClientTransport + 'static, N: Network + 'static> {
    transport: Arc<T>,
    network: Arc<N>,
    alg: Option<Alg>,
    keepalive: Option<Duration>,
    handshake_timeout: Duration,
    reconnect_delay: Duration,
    cred: Option<Cred>,
    encrypt_workers: usize,
}

impl<T: ClientTransport + 'static, N: Network + 'static> ClientBuilder<T, N> {
    pub fn new(transport: T, network: N) -> Self {
        Self {
            transport: Arc::new(transport),
            network: Arc::new(network),
            alg: None,
            keepalive: Some(Duration::from_secs(15)),
            handshake_timeout: Duration::from_secs(5),
            reconnect_delay: Duration::from_secs(3),
            cred: None,
            encrypt_workers: 0,
        }
    }

    /// Set encryption algorithm. Defaults to best algorithm for current CPU.
    pub fn alg(mut self, value: Alg) -> Self {
        self.alg = Some(value);
        self
    }

    /// Set keepalive interval. Useful when behind NAT. `None` disables it.
    pub fn keepalive(mut self, value: Option<Duration>) -> Self {
        self.keepalive = value;
        self
    }

    pub fn handshake_timeout(mut self, value: Duration) -> Self {
        self.handshake_timeout = value;
        self
    }

    pub fn reconnect_delay(mut self, value: Duration) -> Self {
        self.reconnect_delay = value;
        self
    }

    pub fn cred(mut self, cred: Cred) -> Self {
        self.cred = Some(cred);
        self
    }

    /// Number of parallel encrypt workers on the send path. `0`/`1` keeps the
    /// single-task path; `>= 2` enables the WireGuard-style pool that spreads
    /// one flow's encryption across cores with in-order (nonce-order) sends.
    pub fn encrypt_workers(mut self, count: usize) -> Self {
        self.encrypt_workers = count;
        self
    }

    pub fn build(self) -> Result<Client<T, N>, BuildError> {
        let (state, _) = watch::channel(RuntimeState::Connecting);
        Ok(Client {
            transport: self.transport,
            network: self.network,
            alg: self.alg.unwrap_or_default(),
            keepalive: self.keepalive,
            handshake_timeout: self.handshake_timeout,
            reconnect_delay: self.reconnect_delay,
            cred: self.cred.ok_or(BuildError::MissingRequiredField("cred"))?,
            encrypt_workers: self.encrypt_workers,
            state,
        })
    }
}

pub struct Client<T: ClientTransport + 'static, N: Network + 'static> {
    transport: Arc<T>,
    network: Arc<N>,
    alg: Alg,
    keepalive: Option<Duration>,
    handshake_timeout: Duration,
    reconnect_delay: Duration,
    cred: Cred,
    encrypt_workers: usize,
    state: watch::Sender<RuntimeState>,
}

impl<T: ClientTransport + 'static, N: Network + 'static> Client<T, N> {
    pub fn subscribe(&self) -> watch::Receiver<RuntimeState> {
        self.state.subscribe()
    }

    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        let mut set: JoinSet<()> = JoinSet::new();

        // Hot path 1: UDP → decrypt → network
        set.spawn(recv_decrypt_forward(
            self.state.clone(),
            self.transport.clone(),
            self.network.clone(),
        ));

        // Hot path 2: network → encrypt → UDP. With >= 2 encrypt workers, spread
        // one flow's encryption across cores via the pool; else single-task.
        if self.encrypt_workers >= 2 {
            set.spawn(network_pool::encrypt_forward_pool(
                self.state.clone(),
                self.network.clone(),
                self.transport.clone(),
                self.encrypt_workers,
            ));
        } else {
            set.spawn(encrypt_forward(
                self.state.clone(),
                self.network.clone(),
                self.transport.clone(),
            ));
        }

        // Keepalive (optional)
        if let Some(duration) = self.keepalive {
            debug!("starting keepalive with interval {:?}", duration);
            set.spawn(keepalive_sender(
                self.state.clone(),
                self.transport.clone(),
                duration,
            ));
        } else {
            debug!("keepalive disabled");
        }

        // Connector: handles connect + handshake + reconnect
        set.spawn(connector::executor(
            self.state.clone(),
            self.transport.clone(),
            self.cred,
            self.alg,
            self.reconnect_delay,
            self.handshake_timeout,
        ));

        while let Some(res) = set.join_next().await {
            if let Err(e) = res {
                warn!("task panicked: {}", e);
            }
        }

        let state = self.state.borrow().clone();
        Err(match state {
            RuntimeState::Error(err) => err,
            _ => RuntimeError::Unexpected("all tasks exited unexpectedly".into()),
        })
    }
}
