mod connector;
mod data;
mod network;
mod transport;

use crate::{
    gateway::{network::Network, transport::Transport},
    protocol::{Alg, EncryptedData, Packet},
    runtime::{
        cred::Cred,
        error::{BuildError, RuntimeError},
        state::RuntimeState,
        client::{
            data::{data_tun_executor, data_udp_executor, keepalive_sender},
            network::{network_receiver, network_sender},
            transport::{transport_receiver, transport_sender},
        },
    },
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, warn};

pub(super) const AWAIT_STATE_DELAY: Duration = Duration::from_secs(1);
pub(super) const MAX_PACKET_SIZE: usize = 65536;

pub struct ClientBuilder {
    transport: Option<Box<dyn Transport>>,
    network: Option<Box<dyn Network>>,
    addr: Option<SocketAddr>,
    alg: Option<Alg>,
    keepalive: Option<Duration>,
    handshake_timeout: Duration,
    reconnect_delay: Duration,
    cred: Option<Cred>,
    out_transport_buf: usize,
    out_network_buf: usize,
    data_transport_buf: usize,
    data_network_buf: usize,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            transport: None,
            network: None,
            addr: None,
            alg: None,
            keepalive: Some(Duration::from_secs(15)),
            handshake_timeout: Duration::from_secs(5),
            reconnect_delay: Duration::from_secs(3),
            cred: None,
            out_transport_buf: 1000,
            out_network_buf: 1000,
            data_transport_buf: 1000,
            data_network_buf: 1000,
        }
    }

    pub fn transport<T: Transport + 'static>(mut self, value: T) -> Self {
        self.transport = Some(Box::new(value));
        self
    }

    pub fn network<N: Network + 'static>(mut self, value: N) -> Self {
        self.network = Some(Box::new(value));
        self
    }

    pub fn addr(mut self, value: SocketAddr) -> Self {
        self.addr = Some(value);
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

    pub fn out_transport_buf(mut self, value: usize) -> Self {
        self.out_transport_buf = value;
        self
    }

    pub fn out_network_buf(mut self, value: usize) -> Self {
        self.out_network_buf = value;
        self
    }

    pub fn data_transport_buf(mut self, value: usize) -> Self {
        self.data_transport_buf = value;
        self
    }

    pub fn data_network_buf(mut self, value: usize) -> Self {
        self.data_network_buf = value;
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
            addr: self.addr.ok_or(BuildError::MissingRequiredField("addr"))?,
            alg: self.alg.unwrap_or_default(),
            keepalive: self.keepalive,
            handshake_timeout: self.handshake_timeout,
            reconnect_delay: self.reconnect_delay,
            cred: self.cred.ok_or(BuildError::MissingRequiredField("cred"))?,
            out_transport_buf: self.out_transport_buf,
            out_network_buf: self.out_network_buf,
            data_transport_buf: self.data_transport_buf,
            data_network_buf: self.data_network_buf,
            state,
        })
    }
}

pub struct Client {
    transport: Arc<dyn Transport>,
    network: Arc<dyn Network>,
    addr: SocketAddr,
    alg: Alg,
    keepalive: Option<Duration>,
    handshake_timeout: Duration,
    reconnect_delay: Duration,
    cred: Cred,
    out_transport_buf: usize,
    out_network_buf: usize,
    data_transport_buf: usize,
    data_network_buf: usize,
    state: watch::Sender<RuntimeState>,
}

impl Client {
    pub fn subscribe(&self) -> watch::Receiver<RuntimeState> {
        self.state.subscribe()
    }

    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        let (transport_sender_tx, transport_sender_rx) =
            mpsc::channel::<Packet>(self.out_transport_buf);
        let (network_sender_tx, network_sender_rx) =
            mpsc::channel::<Vec<u8>>(self.out_network_buf);
        let (data_transport_tx, data_transport_rx) =
            mpsc::channel::<EncryptedData>(self.data_transport_buf);
        let (data_network_tx, data_network_rx) =
            mpsc::channel::<Vec<u8>>(self.data_network_buf);

        let mut set: JoinSet<()> = JoinSet::new();

        set.spawn(transport_receiver(
            self.state.clone(),
            self.transport.clone(),
            data_transport_tx,
        ));
        set.spawn(transport_sender(
            self.state.clone(),
            self.transport.clone(),
            transport_sender_rx,
        ));
        set.spawn(network_receiver(
            self.state.clone(),
            self.network.clone(),
            data_network_tx,
        ));
        set.spawn(network_sender(
            self.state.clone(),
            self.network.clone(),
            network_sender_rx,
        ));
        set.spawn(data_tun_executor(
            self.state.clone(),
            data_network_rx,
            transport_sender_tx.clone(),
        ));
        set.spawn(data_udp_executor(
            self.state.clone(),
            data_transport_rx,
            network_sender_tx,
        ));

        if let Some(duration) = self.keepalive {
            debug!("starting keepalive with interval {:?}", duration);
            set.spawn(keepalive_sender(
                self.state.clone(),
                transport_sender_tx.clone(),
                duration,
            ));
        } else {
            debug!("keepalive disabled");
        }

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
