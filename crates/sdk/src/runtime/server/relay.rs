//! Transparent (TURN-like) inter-node relay (Phase 4).
//!
//! A client connected to node US can reach another registry node RU without US
//! seeing plaintext: the client runs an end-to-end Noise session with RU and US
//! only shuttles opaque bytes. On `RelayOpen{dest_pk}` US resolves `dest_pk`
//! **through the registry** (so it only ever forwards to known nodes, never
//! arbitrary hosts), binds an ephemeral UDP socket to that destination, and
//! hands the client a `relay_id`. Thereafter:
//!
//! ```text
//! client --RelayData{id,cipher}--> US --cipher--> RU   (via the ephemeral socket)
//! client <--RelayData{id,cipher}-- US <--cipher--- RU   (reader task wraps replies)
//! ```
//!
//! US keeps only `relay_id -> (client_addr, dest, socket)`; it cannot read the
//! inner frames.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::debug;

use super::session::Sessions;
use crate::crypto::PublicKey;
use crate::gateway::transport::Transport;
use crate::runtime::crypto::{relay_opened_frame, write_relay_data};
use crate::time::sec_since_start;

/// Flows idle (no traffic either way) longer than this are reaped.
const RELAY_IDLE_SECS: u64 = 60;
/// Cap on concurrent relay flows per node, to bound sockets/tasks.
const MAX_RELAY_FLOWS: usize = 4096;

struct RelayFlow {
    socket: Arc<UdpSocket>,
    client_addr: Mutex<SocketAddr>,
    last_seen: AtomicU64,
    reader: Mutex<Option<JoinHandle<()>>>,
}

pub(super) struct RelayTable {
    flows: DashMap<u32, Arc<RelayFlow>>,
    next_id: AtomicU32,
}

impl RelayTable {
    pub(super) fn new() -> Self {
        Self {
            flows: DashMap::new(),
            next_id: AtomicU32::new(1),
        }
    }

    fn alloc_id(&self) -> u32 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 && !self.flows.contains_key(&id) {
                return id;
            }
        }
    }
}

/// Handle a `RelayOpen`: resolve the destination via the registry, bind an
/// ephemeral socket, spawn the dest->client reader, and reply `RelayOpened`
/// (`relay_id == 0` on refusal).
pub(super) async fn open<T: Transport + 'static>(
    table: &Arc<RelayTable>,
    sessions: &Sessions,
    transport: &Arc<T>,
    dest_pk_bytes: &[u8],
    client_addr: SocketAddr,
) {
    let refuse = |transport: &Arc<T>| {
        let transport = transport.clone();
        async move {
            let _ = transport
                .send_to(&relay_opened_frame(0), &client_addr)
                .await;
        }
    };

    if table.flows.len() >= MAX_RELAY_FLOWS {
        debug!("relay capacity reached, refusing open from {}", client_addr);
        refuse(transport).await;
        return;
    }
    let Ok(dest_pk) = PublicKey::try_from(dest_pk_bytes) else {
        refuse(transport).await;
        return;
    };
    let Some(dest) = sessions.node_endpoint(&dest_pk) else {
        debug!("relay open to unknown node {}", dest_pk);
        refuse(transport).await;
        return;
    };

    let bind: SocketAddr = if dest.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            debug!("relay bind failed: {}", e);
            refuse(transport).await;
            return;
        }
    };
    if let Err(e) = socket.connect(dest).await {
        debug!("relay connect to {} failed: {}", dest, e);
        refuse(transport).await;
        return;
    }

    let relay_id = table.alloc_id();
    let flow = Arc::new(RelayFlow {
        socket: Arc::new(socket),
        client_addr: Mutex::new(client_addr),
        last_seen: AtomicU64::new(sec_since_start()),
        reader: Mutex::new(None),
    });
    let handle = tokio::spawn(reader_loop(relay_id, flow.clone(), transport.clone()));
    *flow.reader.lock().unwrap() = Some(handle);
    table.flows.insert(relay_id, flow);

    let _ = transport
        .send_to(&relay_opened_frame(relay_id), &client_addr)
        .await;
}

/// Wrap every datagram the destination sends back as `RelayData{relay_id,..}`
/// and deliver it to the flow's current client address.
async fn reader_loop<T: Transport>(relay_id: u32, flow: Arc<RelayFlow>, transport: Arc<T>) {
    let mut recv_buf = [0u8; 65536];
    let mut out = [0u8; 65600];
    loop {
        match flow.socket.recv(&mut recv_buf).await {
            Ok(n) => {
                flow.last_seen.store(sec_since_start(), Ordering::Relaxed);
                let client = *flow.client_addr.lock().unwrap();
                let m = write_relay_data(&mut out, relay_id, &recv_buf[..n]);
                if let Err(e) = transport.send_to(&out[..m], &client).await {
                    debug!("relay {} -> client send failed: {}", relay_id, e);
                }
            }
            Err(e) => {
                debug!("relay {} socket recv ended: {}", relay_id, e);
                break;
            }
        }
    }
}

/// Forward a client's opaque `RelayData` payload to the destination.
pub(super) async fn forward(
    table: &Arc<RelayTable>,
    relay_id: u32,
    payload: &[u8],
    from: SocketAddr,
) {
    let Some(flow) = table.flows.get(&relay_id).map(|f| f.value().clone()) else {
        return;
    };
    flow.last_seen.store(sec_since_start(), Ordering::Relaxed);
    {
        let mut ca = flow.client_addr.lock().unwrap();
        if *ca != from {
            *ca = from; // client roamed / NAT rebind
        }
    }
    if let Err(e) = flow.socket.send(payload).await {
        debug!("relay {} -> dest send failed: {}", relay_id, e);
    }
}

/// Reap flows with no traffic for `RELAY_IDLE_SECS`, aborting their readers.
pub(super) async fn gc_loop(table: Arc<RelayTable>, mut stop: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(RELAY_IDLE_SECS));
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = ticker.tick() => {
                let now = sec_since_start();
                table.flows.retain(|_, flow| {
                    let idle = now.saturating_sub(flow.last_seen.load(Ordering::Relaxed));
                    let alive = idle < RELAY_IDLE_SECS;
                    if !alive
                        && let Some(h) = flow.reader.lock().unwrap().take() {
                        h.abort();
                    }
                    alive
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use crate::gateway::transport::relay::RelayTransport;
    use crate::gateway::transport::udp::UdpTransport;
    use crate::gateway::transport::{ClientTransport, TransportReceiver, TransportSender};
    use crate::identity::AccountKey;
    use crate::protocol::{NodeEntry, PacketRef};
    use crate::registry::{NodeRecord, NodeRegistry};
    use tokio::net::UdpSocket;

    /// End-to-end relay: client (RelayTransport) -> US relay -> dest echo -> back.
    #[tokio::test]
    async fn relay_round_trips_through_us_to_dest() {
        let buf = 1 << 20;
        let lo = "127.0.0.1:0";

        // Destination node: echoes every datagram back to its sender.
        let dest = UdpSocket::bind(lo).await.unwrap();
        let dest_addr = dest.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 65536];
            loop {
                let (n, src) = dest.recv_from(&mut b).await.unwrap();
                let _ = dest.send_to(&b[..n], src).await;
            }
        });

        // US registry knows dest by its pubkey (so relay resolves it).
        let auth = AccountKey::generate();
        let dest_pk = PublicKey::from_secret(&SecretKey::generate_x25519());
        let entry = NodeEntry {
            node_pk: dest_pk.clone(),
            endpoint: dest_addr,
            subnet: "10.0.0.0".parse().unwrap(),
            prefix: 18,
            label: "ru".into(),
        };
        let mut reg = NodeRegistry::new(auth.public());
        reg.merge(NodeRecord::sign(&auth, entry, 1, false));
        let sessions = Sessions::with_config(
            &"10.0.0.0".parse().unwrap(),
            18,
            Vec::new(),
            Vec::new(),
            Some(reg),
        );

        // US relay node: a minimal receive loop dispatching relay frames.
        let us = Arc::new(
            UdpTransport::new_pool(lo.parse().unwrap(), buf, buf, 1)
                .unwrap()
                .pop()
                .unwrap(),
        );
        let us_addr = us.local_addr().unwrap();
        let table = Arc::new(RelayTable::new());
        {
            let (us, sessions, table) = (us.clone(), sessions.clone(), table.clone());
            tokio::spawn(async move {
                let mut b = [0u8; 65536];
                loop {
                    let (n, from) = us.recv_from(&mut b).await.unwrap();
                    match PacketRef::from_bytes(&b[..n]) {
                        Some(PacketRef::RelayOpen(pk)) => {
                            open(&table, &sessions, &us, pk, from).await
                        }
                        Some(PacketRef::RelayData { relay_id, payload }) => {
                            forward(&table, relay_id, payload, from).await
                        }
                        _ => {}
                    }
                }
            });
        }

        // Client tunnels to dest through US.
        let inner = Arc::new(UdpTransport::new(us_addr, buf, buf).unwrap());
        let relay = RelayTransport::new(inner, dest_pk, Duration::from_millis(1000));
        relay.connect().await.expect("relay open");

        relay.send(b"hello relay").await.unwrap();
        let mut rbuf = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_millis(1000), relay.recv(&mut rbuf))
            .await
            .expect("no reply")
            .unwrap();
        assert_eq!(&rbuf[..n], b"hello relay");
    }

    /// A relay to an unknown destination is refused (RelayOpened id = 0).
    #[tokio::test]
    async fn relay_refuses_unknown_destination() {
        let buf = 1 << 20;
        let lo = "127.0.0.1:0";
        let sessions = Sessions::with_config(
            &"10.0.0.0".parse().unwrap(),
            18,
            Vec::new(),
            Vec::new(),
            Some(NodeRegistry::new(AccountKey::generate().public())),
        );
        let us = Arc::new(
            UdpTransport::new_pool(lo.parse().unwrap(), buf, buf, 1)
                .unwrap()
                .pop()
                .unwrap(),
        );
        let us_addr = us.local_addr().unwrap();
        let table = Arc::new(RelayTable::new());
        {
            let (us, sessions, table) = (us.clone(), sessions.clone(), table.clone());
            tokio::spawn(async move {
                let mut b = [0u8; 65536];
                loop {
                    let (n, from) = us.recv_from(&mut b).await.unwrap();
                    if let Some(PacketRef::RelayOpen(pk)) = PacketRef::from_bytes(&b[..n]) {
                        open(&table, &sessions, &us, pk, from).await;
                    }
                }
            });
        }

        let unknown = PublicKey::from_secret(&SecretKey::generate_x25519());
        let inner = Arc::new(UdpTransport::new(us_addr, buf, buf).unwrap());
        let relay = RelayTransport::new(inner, unknown, Duration::from_millis(1000));
        assert!(
            relay.connect().await.is_err(),
            "unknown dest must be refused"
        );
    }
}
