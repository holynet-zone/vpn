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
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::debug;

use super::session::Sessions;
use crate::crypto::PublicKey;
use crate::gateway::transport::udp::UdpTransport;
use crate::gateway::transport::{Transport, TransportReceiver, TransportSender};
use crate::runtime::crypto::{RELAY_DATA_HDR_LEN, relay_opened_frame, write_relay_data};
use crate::time::sec_since_start;

/// Flows idle (no traffic either way) longer than this are reaped.
const RELAY_IDLE_SECS: u64 = 60;
/// Cap on concurrent relay flows per node, to bound sockets/tasks.
const MAX_RELAY_FLOWS: usize = 4096;
/// Datagrams the reader batches per `recvmmsg` / `sendmmsg` on the reverse leg.
const RELAY_BATCH: usize = 32;
/// Per-datagram buffer size (MTU + headroom).
const RELAY_BUF: usize = 65536;
/// So_rcvbuf/So_sndbuf for a relay's ephemeral per-flow socket.
const RELAY_SOCK_BUF: usize = 4 * 1024 * 1024;

struct RelayFlow {
    socket: UdpTransport,
    client_addr: SocketAddr,
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

    // Ephemeral socket bound to :0 and connected to dest (UdpTransport::new).
    let socket = match UdpTransport::new(dest, RELAY_SOCK_BUF, RELAY_SOCK_BUF) {
        Ok(s) => s,
        Err(e) => {
            debug!("relay socket to {} failed: {}", dest, e);
            refuse(transport).await;
            return;
        }
    };

    let relay_id = table.alloc_id();
    let flow = Arc::new(RelayFlow {
        socket,
        client_addr,
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

/// Wrap datagrams the destination sends back as `RelayData{relay_id,..}` and
/// deliver them to the flow's pinned client address. Batches with
/// `recvmmsg` (dest) + `sendmmsg` (client) to cut per-packet syscalls.
async fn reader_loop<T: Transport>(relay_id: u32, flow: Arc<RelayFlow>, transport: Arc<T>) {
    let mut recv_bufs: Vec<Vec<u8>> = (0..RELAY_BATCH).map(|_| vec![0u8; RELAY_BUF]).collect();
    let mut lens = vec![0usize; RELAY_BATCH];
    let mut addrs = vec![SocketAddr::from(([0, 0, 0, 0], 0)); RELAY_BATCH];
    // Wrapped [relay-hdr | payload] frames, reused across batches.
    let mut frames: Vec<Vec<u8>> = (0..RELAY_BATCH)
        .map(|_| vec![0u8; RELAY_DATA_HDR_LEN + RELAY_BUF])
        .collect();

    loop {
        let count = match flow
            .socket
            .recv_mmsg(&mut recv_bufs, &mut lens, &mut addrs)
            .await
        {
            Ok(0) => continue,
            Ok(c) => c,
            Err(e) => {
                debug!("relay {} recv ended: {}", relay_id, e);
                break;
            }
        };
        flow.last_seen.store(sec_since_start(), Ordering::Relaxed);
        let client = flow.client_addr;

        for i in 0..count {
            write_relay_data(&mut frames[i], relay_id, &recv_bufs[i][..lens[i]]);
        }
        let refs: Vec<&[u8]> = (0..count)
            .map(|i| &frames[i][..RELAY_DATA_HDR_LEN + lens[i]])
            .collect();
        if let Err(e) = transport.send_mmsg(&refs, Some(&client)).await {
            debug!("relay {} -> client send failed: {}", relay_id, e);
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
    // relay_id is a guessable counter; only the address that opened the flow may
    // drive it, else a spoofed RelayData would hijack the reverse path.
    if from != flow.client_addr {
        return;
    }
    flow.last_seen.store(sec_since_start(), Ordering::Relaxed);
    if let Err(e) = flow.socket.send(payload).await {
        debug!("relay {} -> dest send failed: {}", relay_id, e);
    }
}

/// Batched forward: the recv loop accumulates `(relay_id, offset, len, from)`
/// into `scratch` across a drain, then flushes here — one `sendmmsg` per flow to
/// its destination, instead of a syscall per packet.
pub(super) async fn forward_batch(
    table: &Arc<RelayTable>,
    scratch: &[u8],
    idx: &[(u32, usize, usize, SocketAddr)],
) {
    let mut done: Vec<u32> = Vec::new();
    for &(id, _, _, _) in idx {
        if done.contains(&id) {
            continue;
        }
        done.push(id);
        let Some(flow) = table.flows.get(&id).map(|f| f.value().clone()) else {
            continue;
        };
        // Only datagrams from the flow's pinned client are forwarded; spoofed
        // ones (guessed relay_id from another address) are dropped.
        let refs: Vec<&[u8]> = idx
            .iter()
            .filter(|e| e.0 == id && e.3 == flow.client_addr)
            .map(|e| &scratch[e.1..e.1 + e.2])
            .collect();
        if refs.is_empty() {
            continue;
        }
        flow.last_seen.store(sec_since_start(), Ordering::Relaxed);
        if let Err(e) = flow.socket.send_mmsg(&refs, None).await {
            debug!("relay {} -> dest batch send failed: {}", id, e);
        }
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

    /// A `RelayData` from an address other than the one that opened the flow is
    /// dropped: the guessable `relay_id` cannot be used to hijack the path.
    #[tokio::test]
    async fn relay_drops_spoofed_source() {
        let buf = 1 << 20;
        let lo = "127.0.0.1:0";

        let dest = UdpSocket::bind(lo).await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

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

        let us = Arc::new(
            UdpTransport::new_pool(lo.parse().unwrap(), buf, buf, 1)
                .unwrap()
                .pop()
                .unwrap(),
        );

        // The legit client's address pins the flow at open time.
        let client = UdpSocket::bind(lo).await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let table = Arc::new(RelayTable::new());
        open(&table, &sessions, &us, dest_pk.as_slice(), client_addr).await;
        let relay_id = 1; // first allocation

        // Spoofed source: must not reach dest.
        let spoof: SocketAddr = "127.0.0.1:1".parse().unwrap();
        forward(&table, relay_id, b"spoofed", spoof).await;
        let mut b = [0u8; 64];
        let leaked = tokio::time::timeout(Duration::from_millis(200), dest.recv_from(&mut b)).await;
        assert!(leaked.is_err(), "spoofed source must be dropped");

        // The pinned client is forwarded normally.
        forward(&table, relay_id, b"legit", client_addr).await;
        let (n, _) = tokio::time::timeout(Duration::from_millis(500), dest.recv_from(&mut b))
            .await
            .expect("legit payload was dropped")
            .unwrap();
        assert_eq!(&b[..n], b"legit");
    }
}
