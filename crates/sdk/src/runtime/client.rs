mod connector;
mod keepalive;
mod network;
mod network_pool;
mod recv;
mod recv_pool;
mod route;

pub use route::plan_route;

use std::{sync::Arc, time::Duration};

use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::{
    gateway::{network::Network, transport::ClientTransport},
    protocol::{Alg, EdgeMetric, NodeEntry},
    runtime::{
        client::{
            keepalive::keepalive_sender, network::encrypt_forward, recv::recv_decrypt_forward,
        },
        cred::Cred,
        error::{BuildError, RuntimeError},
        handshake::{edge_list_step, handshake_step, node_list_step},
        state::{ClientSession, RuntimeState},
    },
};

/// One-shot control query: connect, authenticate, and fetch the node registry,
/// then drop the session. Used by management tooling that only needs the list of
/// nodes without standing up a data tunnel.
pub async fn fetch_node_list<T: ClientTransport>(
    transport: Arc<T>,
    cred: &Cred,
    alg: &Alg,
    timeout: Duration,
) -> Result<Vec<NodeEntry>, RuntimeError> {
    transport
        .connect()
        .await
        .map_err(|e| RuntimeError::IO(format!("connect: {}", e)))?;
    let (payload, transport_state) = handshake_step(transport.clone(), cred, alg, timeout).await?;
    let session = ClientSession::new(transport_state);
    node_list_step(transport, &session, payload.sid, timeout).await
}

/// One-shot control query fetching both the node registry and the inter-node
/// routing overlay over a single session, for client-side path planning.
pub async fn fetch_topology<T: ClientTransport>(
    transport: Arc<T>,
    cred: &Cred,
    alg: &Alg,
    timeout: Duration,
) -> Result<(Vec<NodeEntry>, Vec<EdgeMetric>), RuntimeError> {
    transport
        .connect()
        .await
        .map_err(|e| RuntimeError::IO(format!("connect: {}", e)))?;
    let (payload, transport_state) = handshake_step(transport.clone(), cred, alg, timeout).await?;
    let session = ClientSession::new(transport_state);
    let nodes = node_list_step(transport.clone(), &session, payload.sid, timeout).await?;
    let edges = edge_list_step(transport, &session, payload.sid, timeout).await?;
    Ok((nodes, edges))
}

/// Measure round-trip time to a node's UDP endpoint with a single reflected
/// liveness probe. Returns `None` if no reply arrives within `timeout`. Uses its
/// own ephemeral socket — independent of any tunnel — so reachability is measured
/// from the client's own vantage point.
pub async fn probe_node(
    endpoint: std::net::SocketAddr,
    timeout: Duration,
) -> Option<std::time::Duration> {
    use crate::protocol::PacketRef;
    use crate::runtime::crypto::node_ping_frame;
    use std::time::Instant;
    use tokio::net::UdpSocket;

    let bind = if endpoint.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(endpoint).await.ok()?;

    let nonce = rand::random::<u64>();
    let frame = node_ping_frame(nonce);
    let start = Instant::now();
    sock.send(&frame).await.ok()?;

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    match PacketRef::from_bytes(&buf[..n]) {
        Some(PacketRef::NodePing(got)) if got == nonce => Some(start.elapsed()),
        _ => None,
    }
}

/// Probe every node's endpoint in parallel, pairing each with its measured rtt
/// (`None` = unreachable within `timeout`).
pub async fn probe_nodes(
    nodes: Vec<NodeEntry>,
    timeout: Duration,
) -> Vec<(NodeEntry, Option<std::time::Duration>)> {
    let futs = nodes.into_iter().map(|node| async move {
        let rtt = probe_node(node.endpoint, timeout).await;
        (node, rtt)
    });
    futures::future::join_all(futs).await
}

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
    decrypt_workers: usize,
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
            decrypt_workers: 0,
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

    /// Number of parallel decrypt workers on the receive path. `0`/`1` keeps the
    /// single-task path; `>= 2` enables the WireGuard-style pool that spreads
    /// one flow's decryption across cores with in-order TUN writes. This is the
    /// lever for the reverse (download) direction, which is per-byte single-core
    /// bound.
    pub fn decrypt_workers(mut self, count: usize) -> Self {
        self.decrypt_workers = count;
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
            decrypt_workers: self.decrypt_workers,
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
    decrypt_workers: usize,
    state: watch::Sender<RuntimeState>,
}

impl<T: ClientTransport + 'static, N: Network + 'static> Client<T, N> {
    pub fn subscribe(&self) -> watch::Receiver<RuntimeState> {
        self.state.subscribe()
    }

    pub async fn run(self) -> Result<std::convert::Infallible, RuntimeError> {
        let mut set: JoinSet<()> = JoinSet::new();

        // Hot path 1: UDP → decrypt → network. With >= 2 decrypt workers, spread
        // one flow's decryption across cores via the pool; else single-task.
        if self.decrypt_workers >= 2 {
            set.spawn(recv_pool::recv_decrypt_forward_pool(
                self.state.clone(),
                self.transport.clone(),
                self.network.clone(),
                self.decrypt_workers,
            ));
        } else {
            set.spawn(recv_decrypt_forward(
                self.state.clone(),
                self.transport.clone(),
                self.network.clone(),
            ));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn probe_node_measures_rtt_against_reflector() {
        let reflector = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = reflector.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            if let Ok((n, src)) = reflector.recv_from(&mut buf).await {
                let _ = reflector.send_to(&buf[..n], src).await;
            }
        });
        let rtt = probe_node(addr, Duration::from_millis(500)).await;
        assert!(rtt.is_some(), "reflected probe must yield an rtt");
    }

    #[tokio::test]
    async fn probe_node_times_out_when_silent() {
        // Hold a bound socket that never replies; the probe must time out.
        let _silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = _silent.local_addr().unwrap();
        let rtt = probe_node(addr, Duration::from_millis(150)).await;
        assert!(rtt.is_none());
    }
}
