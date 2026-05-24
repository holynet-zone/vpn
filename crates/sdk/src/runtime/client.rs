mod connector;
mod keepalive;
mod recv;
mod tun;

use std::{sync::Arc, time::Duration};

use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::{
    gateway::{network::Network, transport::ClientTransport},
    protocol::Alg,
    runtime::{
        client::{
            keepalive::keepalive_sender,
            recv::recv_decrypt_forward,
            tun::tun_encrypt_forward,
        },
        cred::Cred,
        error::{BuildError, RuntimeError},
        state::RuntimeState,
    },
};

pub(super) const AWAIT_STATE_DELAY: Duration = Duration::from_secs(1);
pub(super) const MAX_PACKET_SIZE: usize = 65536;

pub struct ClientBuilder {
    transport: Option<Box<dyn ClientTransport>>,
    network: Option<Box<dyn Network>>,
    alg: Option<Alg>,
    keepalive: Option<Duration>,
    handshake_timeout: Duration,
    reconnect_delay: Duration,
    cred: Option<Cred>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            transport: None,
            network: None,
            alg: None,
            keepalive: Some(Duration::from_secs(15)),
            handshake_timeout: Duration::from_secs(5),
            reconnect_delay: Duration::from_secs(3),
            cred: None,
        }
    }

    pub fn transport<T: ClientTransport + 'static>(mut self, value: T) -> Self {
        self.transport = Some(Box::new(value));
        self
    }

    pub fn network<N: Network + 'static>(mut self, value: N) -> Self {
        self.network = Some(Box::new(value));
        self
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

    pub fn build(self) -> Result<Client, BuildError> {
        let (state, _) = watch::channel(RuntimeState::Connecting);
        Ok(Client {
            transport: Arc::from(
                self.transport
                    .ok_or(BuildError::MissingRequiredField("transport"))?,
            ),
            network: Arc::from(
                self.network
                    .ok_or(BuildError::MissingRequiredField("network"))?,
            ),
            alg: self.alg.unwrap_or_default(),
            keepalive: self.keepalive,
            handshake_timeout: self.handshake_timeout,
            reconnect_delay: self.reconnect_delay,
            cred: self.cred.ok_or(BuildError::MissingRequiredField("cred"))?,
            state,
        })
    }
}

pub struct Client {
    transport: Arc<dyn ClientTransport>,
    network: Arc<dyn Network>,
    alg: Alg,
    keepalive: Option<Duration>,
    handshake_timeout: Duration,
    reconnect_delay: Duration,
    cred: Cred,
    state: watch::Sender<RuntimeState>,
}

impl Client {
    pub fn subscribe(&self) -> watch::Receiver<RuntimeState> {
        self.state.subscribe()
    }

    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        let mut set: JoinSet<()> = JoinSet::new();

        // Hot path 1: UDP → decrypt → TUN
        set.spawn(recv_decrypt_forward(
            self.state.clone(),
            self.transport.clone(),
            self.network.clone(),
        ));

        // Hot path 2: TUN → encrypt → UDP
        set.spawn(tun_encrypt_forward(
            self.state.clone(),
            self.network.clone(),
            self.transport.clone(),
        ));

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
