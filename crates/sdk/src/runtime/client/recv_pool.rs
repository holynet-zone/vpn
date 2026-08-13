//! Parallel decrypt pipeline (WireGuard-style) for the client receive path
//! (the reverse / download direction).
//!
//! Mirror of the server's [`recv_pool`](crate::runtime::server) on the client.
//! The single [`recv_decrypt_forward`](super::recv::recv_decrypt_forward) task
//! receives, decrypts, and writes the TUN on one core, so a bulk download is
//! capped by one core's per-byte AEAD + copy budget (this is exactly what caps
//! the reverse direction: it is MTU-insensitive = byte-bandwidth bound, not
//! pps-bound). This spreads one flow's decryption across a worker pool while
//! preserving on-wire order:
//!
//! ```text
//!   reader ──batch 0,1,2…──▶ worker[batch % W] ──▶ writer (reads
//!   (connected recvmmsg,     (W tasks decrypt a    done[expected % W] in
//!    one batch of up to       whole batch each)     strict rotation → order
//!    MMSG_BATCH datagrams)                          restored) ──▶ TUN
//! ```
//!
//! Same batch-granular handoff and rotation-ordering as the server pool (see its
//! module docs). Differences: a connected socket (no per-datagram addr), a single
//! session taken from [`RuntimeState`] (attached per batch, refreshed on
//! reconnect), and control frames handled inline — keepalive logs its RTT,
//! `Disconnect` signals a reconnect. The anti-replay check runs in the single
//! writer, in order.

use std::ops::Deref;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::gateway::network::{GroState, Network, TUN_BATCH_SIZE, TUN_SEND_OFFSET};
use crate::gateway::transport::ClientTransport;
use crate::protocol::PacketRef;
use crate::runtime::crypto::{DataServerActionRef, noise_decrypt_data_server_into};
use crate::runtime::state::{ClientSession, RuntimeState};
use crate::time::{format_duration_millis, micros_since_start};

/// Datagrams the reader gathers per `recvmmsg` and carries as one [`Batch`]
/// through the pipeline (<= transport's `MAX_MMSG`). Amortisation unit: one
/// channel message + one task wakeup covers up to this many packets.
const MMSG_BATCH: usize = 32;
/// Depth (in batches) of each `reader → worker` and `worker → writer` channel.
const CHAN_CAP: usize = 2;

/// What the writer should do with a processed slot.
#[derive(Clone, Copy)]
enum SlotAction {
    /// Decrypted IP packet sits in `plain[TUN_SEND_OFFSET..]`; write it to TUN
    /// after an in-order replay check.
    Forward,
    /// Nothing to write (parse/decrypt failure, replay, keepalive, disconnect, or
    /// a handshake handled out of band). Just recycle the slot.
    Skip,
}

/// One datagram's worth of work inside a [`Batch`].
struct Slot {
    /// Raw datagram bytes received from the socket (`[..cipher_len]` valid).
    cipher: Vec<u8>,
    cipher_len: usize,
    /// Set by the worker for `Forward` slots; used by the writer's replay check.
    nonce: u64,
    /// Decrypted frame; IP packet lives at `[TUN_SEND_OFFSET..]`, `len()` set by
    /// the worker. Swapped into the writer's TUN batch on `Forward`.
    plain: Vec<u8>,
    action: SlotAction,
}

impl Slot {
    fn new(cipher_cap: usize, seg: usize) -> Self {
        Self {
            cipher: vec![0u8; cipher_cap],
            cipher_len: 0,
            nonce: 0,
            plain: vec![0u8; seg],
            action: SlotAction::Skip,
        }
    }
}

/// A recyclable burst of up to [`MMSG_BATCH`] datagrams travelling
/// reader → worker → writer → free as a single unit. `slots[..len]` are valid.
/// `session` is the session active when the batch was received.
struct Batch {
    seq: u64,
    len: usize,
    session: Option<ClientSession>,
    slots: Vec<Slot>,
}

impl Batch {
    fn new(cipher_cap: usize, seg: usize) -> Self {
        Self {
            seq: 0,
            len: 0,
            session: None,
            slots: (0..MMSG_BATCH).map(|_| Slot::new(cipher_cap, seg)).collect(),
        }
    }
}

/// Spawn the reader + `workers` decrypt tasks + writer and run until the runtime
/// state goes to `Error` or the channels close.
pub(super) async fn recv_decrypt_forward_pool<T: ClientTransport + 'static, N: Network + 'static>(
    state_tx: watch::Sender<RuntimeState>,
    transport: Arc<T>,
    network: Arc<N>,
    workers: usize,
) {
    let mtu = network.mtu() as usize;
    let seg = mtu + 128 + TUN_SEND_OFFSET;
    let cipher_cap = mtu + 128;
    let batches_total = (workers * (2 * CHAN_CAP + 2)).max(16);

    let (free_tx, free_rx) = mpsc::channel::<Box<Batch>>(batches_total);
    for _ in 0..batches_total {
        free_tx
            .try_send(Box::new(Batch::new(cipher_cap, seg)))
            .expect("freelist prefill fits its own capacity");
    }

    let mut work_tx = Vec::with_capacity(workers);
    let mut done_rx = Vec::with_capacity(workers);
    let mut set: JoinSet<()> = JoinSet::new();

    for _ in 0..workers {
        let (wtx, wrx) = mpsc::channel::<Box<Batch>>(CHAN_CAP);
        let (dtx, drx) = mpsc::channel::<Box<Batch>>(CHAN_CAP);
        work_tx.push(wtx);
        done_rx.push(drx);
        set.spawn(worker(wrx, dtx, state_tx.clone(), seg));
    }

    set.spawn(reader(
        state_tx.clone(),
        transport.clone(),
        workers,
        cipher_cap,
        free_rx,
        free_tx.clone(),
        work_tx,
    ));
    set.spawn(writer(state_tx.clone(), network.clone(), workers, done_rx, free_tx.clone()));
    drop(free_tx);

    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            error!("client decrypt pool task failed: {}", e);
        }
    }
    debug!("client recv_decrypt_forward_pool stopped");
}

/// Owns the socket. Awaits the first datagram, then drains any others already
/// queued (`try_recv`, no wait) into one free [`Batch`], attaches the current
/// session, tags it with a monotonic `seq`, and round-robins the whole batch to
/// `work[seq % workers]`.
///
/// Uses `recv` + `try_recv` (not `recvmmsg`) deliberately: this is a single
/// connected flow where a `recvmmsg` wake almost always carries one datagram
/// (see the reverted recvmmsg experiment), and `recv`/`try_recv` is the exact
/// pattern the proven single-task path uses on this same connected socket.
async fn reader<T: ClientTransport>(
    state_tx: watch::Sender<RuntimeState>,
    transport: Arc<T>,
    workers: usize,
    _cipher_cap: usize,
    mut free_rx: mpsc::Receiver<Box<Batch>>,
    free_tx: mpsc::Sender<Box<Batch>>,
    work_tx: Vec<mpsc::Sender<Box<Batch>>>,
) {
    let w = workers as u64;
    let mut seq: u64 = 0;

    let mut state_rx = state_tx.subscribe();

    let mut is_connected = false;
    let mut session: Option<ClientSession> = None;

    'main: loop {
        // Pause receiving until connected to avoid processing stale data. Adopt
        // the *current* state first (so an already-`Connected` state set before
        // we subscribed is picked up, not just future changes), then block for
        // the next change while still disconnected.
        if !is_connected {
            let is_error = matches!(&*state_rx.borrow(), RuntimeState::Error(_));
            update_state(&mut state_rx, &mut is_connected, &mut session);
            if is_error {
                break;
            }
            if !is_connected {
                if state_rx.changed().await.is_err() {
                    break;
                }
                continue;
            }
        }

        // A free batch to receive into. The batch's own slot buffers back the
        // recv, so holding it here only applies backpressure.
        let mut batch = tokio::select! {
            _ = state_rx.changed() => {
                let is_error = matches!(&*state_rx.borrow(), RuntimeState::Error(_));
                update_state(&mut state_rx, &mut is_connected, &mut session);
                if is_error { break; }
                continue;
            }
            b = free_rx.recv() => match b { Some(b) => b, None => break },
        };

        // Await the first datagram (or a state change).
        let n = tokio::select! {
            _ = state_rx.changed() => {
                let is_error = matches!(&*state_rx.borrow(), RuntimeState::Error(_));
                update_state(&mut state_rx, &mut is_connected, &mut session);
                let _ = free_tx.try_send(batch); // return the unused batch
                if is_error { break; }
                continue;
            }
            r = transport.recv(&mut batch.slots[0].cipher) => match r {
                Ok(n) => n,
                Err(e) => {
                    warn!("transport recv error, reconnecting: {}", e);
                    let _ = free_tx.try_send(batch);
                    if state_tx.send(RuntimeState::Connecting).is_err() { break; }
                    continue;
                }
            }
        };

        let Some(ref sess) = session else {
            warn!("received data before connected state, dropping");
            let _ = free_tx.try_send(batch);
            continue;
        };

        batch.slots[0].cipher_len = n;
        let mut len = 1usize;
        // Drain everything already queued without waiting.
        while len < MMSG_BATCH {
            match transport.try_recv(&mut batch.slots[len].cipher) {
                Ok(n2) => {
                    batch.slots[len].cipher_len = n2;
                    len += 1;
                }
                Err(_) => break,
            }
        }

        batch.len = len;
        batch.session = Some(sess.clone());
        batch.seq = seq;
        let k = (seq % w) as usize;
        seq = seq.wrapping_add(1);
        if work_tx[k].send(batch).await.is_err() {
            break 'main;
        }
    }
    debug!("client decrypt pool reader stopped");
}

/// Adopt the current `RuntimeState` into the reader's connection view, marking it
/// seen (`borrow_and_update`) so a following `changed()` waits for the *next*
/// change instead of returning immediately on the one we just consumed.
fn update_state(
    state_rx: &mut watch::Receiver<RuntimeState>,
    is_connected: &mut bool,
    session: &mut Option<ClientSession>,
) {
    match state_rx.borrow_and_update().deref() {
        RuntimeState::Connecting => {
            *is_connected = false;
            *session = None;
        }
        RuntimeState::Connected((_, s)) => {
            *session = Some(s.clone());
            *is_connected = true;
        }
        _ => {}
    }
}

/// Decrypts every slot in each incoming batch, then forwards the whole batch to
/// the writer (skipped slots included, so the writer's rotation stays in lockstep
/// with the batch `seq`).
async fn worker(
    mut work_rx: mpsc::Receiver<Box<Batch>>,
    done_tx: mpsc::Sender<Box<Batch>>,
    state_tx: watch::Sender<RuntimeState>,
    seg: usize,
) {
    while let Some(mut batch) = work_rx.recv().await {
        match batch.session.clone() {
            Some(session) => {
                for si in 0..batch.len {
                    decrypt_one(&mut batch.slots[si], &session, seg, &state_tx);
                }
            }
            None => {
                for si in 0..batch.len {
                    batch.slots[si].action = SlotAction::Skip;
                }
            }
        }
        if done_tx.send(batch).await.is_err() {
            break;
        }
    }
    debug!("client decrypt pool worker stopped");
}

/// Decrypt/dispatch a single slot in place, setting its `action` for the writer.
/// Replay is NOT checked here (the writer does it in order); a replayed datagram
/// is decrypted and then dropped, like the server pool.
fn decrypt_one(slot: &mut Slot, session: &ClientSession, seg: usize, state_tx: &watch::Sender<RuntimeState>) {
    slot.action = SlotAction::Skip;

    if slot.cipher_len == 0 || slot.cipher_len >= slot.cipher.len() {
        warn!("dropping transport packet (size {})", slot.cipher_len);
        return;
    }

    match PacketRef::from_bytes(&slot.cipher[..slot.cipher_len]) {
        None => warn!("failed to parse transport packet"),

        Some(PacketRef::DataServer { nonce, ciphertext }) => {
            slot.plain.resize(seg, 0);
            let base = slot.plain.as_ptr() as usize;
            let dec = noise_decrypt_data_server_into(
                ciphertext,
                &session.noise,
                &mut slot.plain[TUN_SEND_OFFSET..],
                nonce,
            );
            match dec {
                Err(e) => warn!("decrypt failed: {}", e),
                Ok(DataServerActionRef::Forward(packet)) => {
                    let start = packet.as_ptr() as usize - base;
                    let len = packet.len();
                    slot.plain.copy_within(start..start + len, TUN_SEND_OFFSET);
                    slot.plain.truncate(TUN_SEND_OFFSET + len);
                    slot.nonce = nonce;
                    slot.action = SlotAction::Forward;
                }
                Ok(DataServerActionRef::KeepAlive(ts)) => {
                    info!("keepalive rtt: {}", format_duration_millis(ts, micros_since_start()));
                }
                Ok(DataServerActionRef::Disconnect(code)) => {
                    warn!("server disconnect code {}", code);
                    let _ = state_tx.send(RuntimeState::Connecting);
                }
            }
        }

        Some(PacketRef::HandshakeResponder(_)) => {
            // Connector handles the handshake separately; drop it here.
        }

        Some(_) => warn!("unexpected packet variant on client"),
    }
}

/// Reassembles the decrypted stream in batch `seq` order by reading `done[expected
/// % workers]` in strict rotation, batches `Forward` packets across incoming
/// batches, and flushes them to the TUN in one GRO-merged `send_multiple`. The
/// anti-replay check runs here, single-threaded and in order.
async fn writer<N: Network>(
    state_tx: watch::Sender<RuntimeState>,
    network: Arc<N>,
    workers: usize,
    mut done_rx: Vec<mpsc::Receiver<Box<Batch>>>,
    free_tx: mpsc::Sender<Box<Batch>>,
) {
    let w = workers as u64;
    let mut state_rx = state_tx.subscribe();
    let mut gro = GroState::new();
    // Sized lazily from the first real batch's slot capacity (all slots share the
    // same seg), so we never hard-code it here.
    let mut tun_batch: Vec<Vec<u8>> = Vec::new();
    let mut tun_len = 0usize;
    let mut expected: u64 = 0;

    loop {
        let k = (expected % w) as usize;

        // Non-blocking first, so a run of ready batches coalesces into one write.
        let mut batch = match done_rx[k].try_recv() {
            Ok(b) => b,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
            Err(mpsc::error::TryRecvError::Empty) => {
                if tun_len > 0 {
                    flush(&network, &mut gro, &mut tun_batch, tun_len).await;
                    tun_len = 0;
                }
                tokio::select! {
                    _ = state_rx.changed() => {
                        if matches!(state_rx.borrow().deref(), RuntimeState::Error(_)) {
                            break;
                        }
                        continue;
                    }
                    r = done_rx[k].recv() => match r { Some(b) => b, None => break },
                }
            }
        };
        expected = expected.wrapping_add(1);

        if tun_batch.is_empty() && batch.len > 0 {
            let cap = batch.slots[0].plain.capacity().max(1);
            tun_batch = (0..TUN_BATCH_SIZE).map(|_| vec![0u8; cap]).collect();
        }

        for si in 0..batch.len {
            if let SlotAction::Forward = batch.slots[si].action {
                let ok = match &batch.session {
                    Some(session) => {
                        session.recv_window.lock().unwrap().check_and_update(batch.slots[si].nonce)
                    }
                    None => false,
                };
                if ok {
                    std::mem::swap(&mut batch.slots[si].plain, &mut tun_batch[tun_len]);
                    tun_len += 1;
                    if tun_len == TUN_BATCH_SIZE {
                        flush(&network, &mut gro, &mut tun_batch, tun_len).await;
                        tun_len = 0;
                    }
                } else {
                    warn!("replay/stale nonce {} from server", batch.slots[si].nonce);
                }
            }
        }

        // Drop the session ref so a recycled batch doesn't pin the session.
        batch.session = None;
        let _ = free_tx.try_send(batch);
    }

    if tun_len > 0 {
        flush(&network, &mut gro, &mut tun_batch, tun_len).await;
    }
    debug!("client decrypt pool writer stopped");
}

/// Write `tun_batch[..len]` to the TUN in one GRO-merged `send_multiple`.
async fn flush<N: Network>(network: &Arc<N>, gro: &mut GroState, tun_batch: &mut [Vec<u8>], len: usize) {
    if let Err(e) = network.send_multiple(gro, &mut tun_batch[..len], TUN_SEND_OFFSET).await {
        warn!("network send failed: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::network::{NetworkReceiver, NetworkSender};
    use crate::gateway::transport::TransportSender;
    use crate::gateway::transport::mock::MockTransport;
    use crate::protocol::handshake::HandshakeResponderPayload;
    use crate::runtime::crypto::{encode_data_server_packet, make_noise_pair_for_test};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Mock TUN that records every packet handed to it, in order.
    struct RecordingNetwork {
        writes: mpsc::UnboundedSender<Vec<u8>>,
        mtu: u16,
    }

    impl NetworkSender for RecordingNetwork {
        async fn send_to(&self, data: &[u8], _addr: &SocketAddr) -> io::Result<usize> {
            self.send(data).await
        }
        async fn send(&self, data: &[u8]) -> io::Result<usize> {
            let _ = self.writes.send(data.to_vec());
            Ok(data.len())
        }
    }

    impl NetworkReceiver for RecordingNetwork {
        async fn recv_from(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        async fn recv(&self, _buffer: &mut [u8]) -> io::Result<usize> {
            std::future::pending().await
        }
    }

    impl Network for RecordingNetwork {
        fn mtu(&self) -> u16 {
            self.mtu
        }
    }

    /// N distinct DataServer packets pushed through the client pool must arrive at
    /// the TUN in send order, none lost or duplicated, regardless of worker
    /// interleaving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn client_pool_preserves_order_and_delivers_all() {
        const N: u64 = 200;
        const WORKERS: usize = 4;

        // Server encrypts DataServer with `resp`; the client decrypts with `init`.
        let (client_state, server_state) = make_noise_pair_for_test();
        let session = ClientSession::new(client_state);

        // client_tp is what the pool receives on; server_tp injects datagrams.
        let (client_tp, server_tp) = MockTransport::create_pair();
        let client_tp = Arc::new(client_tp);
        let peer: SocketAddr = "127.0.0.1:10001".parse().unwrap();

        let (writes_tx, mut writes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let network = Arc::new(RecordingNetwork { writes: writes_tx, mtu: 1420 });

        let (state_tx, _state_rx) = watch::channel(RuntimeState::Connecting);

        let pool = tokio::spawn(recv_decrypt_forward_pool(
            state_tx.clone(),
            client_tp.clone(),
            network,
            WORKERS,
        ));

        // Move to Connected so the reader starts consuming the socket.
        let payload = HandshakeResponderPayload {
            sid: 1,
            ipaddr: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
        };
        state_tx
            .send(RuntimeState::Connected((payload, session)))
            .unwrap();

        // Each packet's payload starts with its sequence number.
        for seq in 0..N {
            let mut payload = vec![0u8; 64];
            payload[..8].copy_from_slice(&seq.to_le_bytes());
            let mut frame = vec![0u8; 65600];
            let n = encode_data_server_packet(&payload, &server_state, seq, &mut frame).unwrap();
            server_tp.send_to(&frame[..n], &peer).await.unwrap();
        }

        for expected in 0..N {
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), writes_rx.recv())
                .await
                .expect("timed out waiting for TUN write")
                .expect("recording channel closed");
            let seq = u64::from_le_bytes(got[..8].try_into().unwrap());
            assert_eq!(seq, expected, "out-of-order TUN write");
            assert_eq!(got.len(), 64, "payload length mismatch");
        }

        pool.abort();
    }
}
