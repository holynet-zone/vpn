mod connector;
mod data;
mod network;
mod transport;


use crate::{
    gateway::{
        network::Network,
        transport::Transport
    },
    runtime::{
        state::RuntimeState,
        error::RuntimeError,
        worker::{
            data::{data_tun_executor, data_udp_executor, keepalive_sender},
            transport::{transport_listener, transport_sender},
            tun::{tun_listener, tun_sender},
        }
    },
};
use crate::protocol::{Alg, EncryptedData, Packet};
use std::time::Duration;
use std::{
    net::SocketAddr,
    sync::Arc
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};
use crate::error::{BuildError, RuntimeError};
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::runtime::client::data::{data_tun_executor, data_udp_executor, keepalive_sender};
use crate::runtime::client::transport::{transport_listener, transport_sender};
use crate::runtime::client::network::{tun_listener, tun_sender};
use crate::runtime::cred::Cred;


const AWAIT_STATE_DELAY: Duration = Duration::from_secs(1);
const MAX_PACKET_SIZE: usize = 65536;

pub struct ClientBuilder {
    transport: Option<Box<dyn Transport>>,
    network: Option<Box<dyn Network>>,
    addr: Option<SocketAddr>,
    alg: Option<Alg>,
    keepalive: Option<Duration>,
    handshake_timeout: Duration,
    reconnect_delay: Duration,
    cred: Option<Cred>,
    // Buffer sizes
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
            out_transport_buf: usize::MAX,
            out_network_buf: usize::MAX,
            data_transport_buf: usize::MAX,
            data_network_buf: usize::MAX,
        }
    }

    pub fn transport<T: Transport + 'static>(mut self, value: T) -> Self {
        self.transport = Some(Box::new(value));
        self
    }

    pub fn network<N: Into<dyn Network> + 'static>(mut self, value: N) -> Self {
        self.network = Some(Box::new(value.into()));
        self
    }

    /// Set server address
    pub fn addr(mut self, value: SocketAddr) -> Self {
        self.addr = Some(value);
        self
    }

    /// Set encryption algorithm
    /// If not set, the default algorithm will be used
    ///
    /// # Arguments
    /// * `value` - Encryption algorithm
    ///
    /// # Default
    /// The default algorithm is calculated based on the processor's capabilities
    ///
    pub fn alg(mut self, value: Alg) -> Self {
        self.alg = Some(value);
        self
    }

    /// Set keepalive interval
    /// If not set, keepalive is disabled
    ///
    /// This is useful if the client is behind nat!
    ///
    /// # Note
    /// If the interval is too short, it may cause unnecessary network traffic.
    /// If the interval is too long, it may cause the connection to be dropped by nat
    ///
    /// # Default
    /// The default value is 15 seconds
    ///
    /// # Arguments
    /// * `value` - Keepalive interval
    pub fn keepalive(mut self, value: Duration) -> Self {
        self.keepalive = Some(value);
        self
    }

    /// Set handshake timeout
    ///
    /// # Arguments
    /// * `value` - Handshake timeout duration
    /// # Default
    /// The default value is 5 seconds
    pub fn handshake_timeout(mut self, value: Duration) -> Self {
        self.handshake_timeout = value;
        self
    }
    
    /// Set reconnect delay
    /// If not set, the default value is 3 seconds
    /// 
    /// # Arguments
    /// * `value` - Reconnect delay duration
    /// # Default
    /// The default value is 3 seconds
    pub fn reconnect_delay(mut self, value: Duration) -> Self {
        self.reconnect_delay = value;
        self
    }

    /// Set credentials
    ///
    /// # Arguments
    /// * `sk` - Client's secret key
    /// * `psk` - Pre-shared key
    /// * `spk` - Server's public key
    pub fn cred(mut self, sk: [u8; 32], psk: [u8; 32], spk: [u8; 32]) -> Self {
        self.cred = Some(Cred { sk, psk, spk });
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
            transport: Arc::from(self.transport.ok_or(BuildError::MissingRequiredField("missing transport"))?),
            network: Arc::from(self.network.ok_or(BuildError::MissingRequiredField("missing network"))?),
            addr: self.addr.ok_or(BuildError::MissingRequiredField)?,
            alg: self.alg.unwrap_or_default(),
            keepalive: self.keepalive,
            handshake_timeout: self.handshake_timeout,
            cred: self.cred.ok_or(BuildError::MissingRequiredField("missing credentials"))?,
            out_transport_buf: self.out_transport_buf,
            out_network_buf: self.out_network_buf,
            data_transport_buf: self.data_transport_buf,
            data_network_buf: self.data_network_buf,
            state
        })
    }
}


pub struct Client {
    transport: Arc<dyn Transport>,
    network: Arc<dyn Network>, // TODO : support multiple network types
    addr: SocketAddr,
    alg: Alg,
    keepalive: Option<Duration>,
    handshake_timeout: Duration,
    cred: Cred,
    // Buffer sizes
    out_transport_buf: usize,
    out_network_buf: usize,
    data_transport_buf: usize,
    data_network_buf: usize,
    // Internal state
    state: watch::Sender<RuntimeState>
}

impl Client {
    pub async fn run(&mut self) -> Result<!, RuntimeError> {
        let (transport_sender_tx, transport_sender_rx) = mpsc::channel::<Packet>(self.out_transport_buf);
        let (network_sender_tx, network_sender_rx) = mpsc::channel::<Vec<u8>>(self.out_network_buf);
        let (data_transport_tx, data_transport_rx) = mpsc::channel::<EncryptedData>(self.data_transport_buf);
        let (data_network_tx, data_network_rx) = mpsc::channel::<Vec<u8>>(self.data_network_buf);


        let mut set = JoinSet::new();

        // Handle incoming transport packets
        set.spawn(transport_listener(self.state.clone(), self.transport.clone(), data_transport_tx));
        // Handle outgoing transport packets
        set.spawn(transport_sender(self.state.clone(), self.transport.clone(), transport_sender_rx));
        // Handle incoming net packets
        set.spawn(tun_listener(
            self.state.clone(),
            self.network.clone(),
            data_network_tx.clone()
        ));
        // Handle outgoing net packets
        set.spawn(tun_sender(
            self.state.clone(),
            self.network.clone(),
            network_sender_rx
        ));

        // Executors
        set.spawn(data_tun_executor(
            self.state.clone(),
            data_network_rx,
            transport_sender_tx.clone(),
        ));

        set.spawn(data_udp_executor(
            self.state.clone(),
            data_transport_rx,
            network_sender_tx
        ));


        match self.keepalive {
            Some(duration) => {
                debug!("starting keepalive with interval {:?}", duration);
                set.spawn(keepalive_sender(
                    self.state.clone(),
                    transport_sender_tx,
                    duration,
                ));
            },
            None => debug!("keepalive is disabled")
        }

        // connector
        set.spawn(connector::executor(
            self.transport,
            self.state.clone(),
            self.cred,
            self.alg,
            self.handshake_timeout
        ));

        while let Some(res) = set.join_all().await {
            match res {
                Ok(val) => debug!("task exited: {val:?}"),
                Err(e) => debug!("task exited with error: {e}"),
            }
        }
        Err(match self.state {
            RuntimeState::Error(err) => err,
            _ => RuntimeError::Unexpected("all tasks exited unexpectedly".into())
        })
    }
}
