//! Parallel decrypt pipeline (WireGuard-style) for the server receive path.
//!
//! The plain [`recv_decrypt_forward`](super::recv::recv_decrypt_forward) task
//! runs the whole receive → decrypt → TUN-write chain on a single core. With
//! `SO_REUSEPORT` the kernel pins one UDP flow to exactly one socket (=one such
//! task), so a single bulk flow is capped by one core's AEAD throughput even
//! though the box has many idle cores. This module spreads that one flow's
//! decryption across a worker pool while preserving on-wire order:
//!
//! ```text
//!   reader ──seq 0,1,2,3,4,5…──▶ worker[seq % W] ──▶ writer (reads
//!   (one socket, assigns a       (W tasks decrypt   done[expected % W] in
//!    monotonic seq, round-        in parallel)       strict rotation → global
//!    robins to workers)                              order restored) ──▶ TUN
//! ```
//!
//! ## Why the rotation restores order without a reorder buffer
//!
//! The reader assigns a strictly increasing `seq` and sends `seq` to
//! `work[seq % W]`. Each worker's input and output channels are FIFO, so
//! `done[k]` yields exactly the sub-sequence `k, k+W, k+2W, …` in increasing
//! order. The writer consumes `done[0], done[1], …, done[W-1], done[0], …`,
//! i.e. `seq` `0, 1, 2, …` — the exact order the datagrams were received (which
//! is the order the sender put them on the wire). No per-packet reorder buffer,
//! no sequence heap.
//!
//! ## Replay check lives in the writer
//!
//! The anti-replay window is checked in the single-threaded writer, in `seq`
//! order — never in the parallel workers. That keeps the per-session replay
//! `Mutex` uncontended (a hot single flow would otherwise have all W workers
//! hammering one lock every packet). A replayed datagram is still decrypted
//! (wasted AEAD work) but then dropped; replays are attack/dup-only and rare,
//! so this matches WireGuard-go's design.
//!
//! ## Zero-allocation steady state
//!
//! A fixed pool of [`Slot`] buffers circulates: `free → reader (recv into it) →
//! worker (decrypt) → writer (write to TUN) → free`. The writer swaps a slot's
//! decrypted buffer into its contiguous TUN batch (tun-rs wants `&mut
//! [Vec<u8>]`) and hands the swapped-out buffer back with the recycled slot, so
//! the buffer count is conserved with no per-packet heap traffic.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, warn};

use super::session::{Session, Sessions};
use crate::gateway::network::{GroState, Network, TUN_BATCH_SIZE, TUN_SEND_OFFSET};
use crate::gateway::transport::Transport;
use crate::protocol::{DataServerBody, EncryptedHandshake, PacketRef, SessionId};
use crate::runtime::crypto::{
    DataClientActionRef, encode_data_server_frame, noise_decrypt_data_client_into, noise_encrypt,
};
use crate::time::sec_since_start;

/// In-flight slots per worker. Bounds memory (each slot ≈ MTU + a TUN buffer)
/// while leaving enough depth to keep every worker and the writer busy.
const SLOTS_PER_WORKER: usize = 8;
/// Depth of each `reader → worker` and `worker → writer` channel.
const CHAN_CAP: usize = 4;

/// What the writer should do with a processed slot.
enum SlotAction {
    /// Decrypted IP packet sits in `plain[TUN_SEND_OFFSET..]`; write it to TUN
    /// after an in-order replay check.
    Forward,
    /// Nothing to write (parse/decrypt failure, replay, keepalive handled in the
    /// worker, or a handshake forwarded out of band). Just recycle the slot.
    Skip,
}

/// One recyclable unit of work travelling reader → worker → writer → free.
struct Slot {
    seq: u64,
    addr: SocketAddr,
    /// Raw datagram bytes received from the socket (`[..cipher_len]` valid).
    cipher: Vec<u8>,
    cipher_len: usize,
    /// Set by the worker for `Forward` slots; used by the writer's replay check.
    nonce: u64,
    session: Option<Arc<Session>>,
    /// Decrypted frame; IP packet lives at `[TUN_SEND_OFFSET..]`, `len()` set by
    /// the worker. Swapped into the writer's TUN batch on `Forward`.
    plain: Vec<u8>,
    action: SlotAction,
}

impl Slot {
    fn new(cipher_cap: usize, seg: usize) -> Self {
        Self {
            seq: 0,
            addr: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            cipher: vec![0u8; cipher_cap],
            cipher_len: 0,
            nonce: 0,
            session: None,
            plain: vec![0u8; seg],
            action: SlotAction::Skip,
        }
    }
}

/// Spawn the reader + `workers` decrypt tasks + writer and run until stop.
///
/// `workers` must be >= 2 (the caller uses the single-task path otherwise).
pub(super) async fn recv_decrypt_forward_pool<T: Transport + 'static, N: Network + 'static>(
    stop: watch::Receiver<bool>,
    transport: Arc<T>,
    network: Arc<N>,
    sessions: Sessions,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    inf_sessions_timeout: bool,
    workers: usize,
) {
    let mtu = network.mtu() as usize;
    let seg = mtu + 128 + TUN_SEND_OFFSET;
    let cipher_cap = mtu + 128;
    let slots_total = workers * SLOTS_PER_WORKER;

    // Freelist, prefilled with every slot the pipeline owns.
    let (free_tx, free_rx) = mpsc::channel::<Box<Slot>>(slots_total);
    for _ in 0..slots_total {
        free_tx
            .try_send(Box::new(Slot::new(cipher_cap, seg)))
            .expect("freelist prefill fits its own capacity");
    }

    let mut work_tx = Vec::with_capacity(workers);
    let mut done_rx = Vec::with_capacity(workers);
    let mut set: JoinSet<()> = JoinSet::new();

    for _ in 0..workers {
        let (wtx, wrx) = mpsc::channel::<Box<Slot>>(CHAN_CAP);
        let (dtx, drx) = mpsc::channel::<Box<Slot>>(CHAN_CAP);
        work_tx.push(wtx);
        done_rx.push(drx);
        set.spawn(worker(
            wrx,
            dtx,
            transport.clone(),
            sessions.clone(),
            handshake_tx.clone(),
            inf_sessions_timeout,
            seg,
        ));
    }

    set.spawn(reader(
        stop.clone(),
        transport.clone(),
        workers,
        free_rx,
        free_tx.clone(),
        work_tx,
    ));
    set.spawn(writer(
        stop.clone(),
        network.clone(),
        workers,
        done_rx,
        free_tx.clone(),
        seg,
    ));
    drop(free_tx);

    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            error!("decrypt pool task failed: {}", e);
        }
    }
    debug!("recv_decrypt_forward_pool stopped");
}

/// Owns the socket. Receives datagrams directly into free slots, tags each with
/// a monotonic `seq`, and round-robins them to `work[seq % workers]`. Draining
/// pulls already-queued datagrams without blocking, exactly like the single
/// task path, so a lone packet adds no latency.
async fn reader<T: Transport>(
    mut stop: watch::Receiver<bool>,
    transport: Arc<T>,
    workers: usize,
    mut free_rx: mpsc::Receiver<Box<Slot>>,
    free_tx: mpsc::Sender<Box<Slot>>,
    work_tx: Vec<mpsc::Sender<Box<Slot>>>,
) {
    let w = workers as u64;
    let mut seq: u64 = 0;

    loop {
        // Grab a buffer to receive into (backpressure: block if the pool is
        // saturated, letting the socket queue absorb the burst).
        let mut slot = tokio::select! {
            _ = stop.changed() => break,
            s = free_rx.recv() => match s { Some(s) => s, None => break },
        };

        let (n, addr) = tokio::select! {
            _ = stop.changed() => break,
            r = transport.recv_from(&mut slot.cipher) => match r {
                Ok(v) => v,
                Err(e) => {
                    warn!("transport recv error: {}", e);
                    let _ = free_tx.try_send(slot);
                    continue;
                }
            }
        };

        slot.cipher_len = n;
        slot.addr = addr;
        slot.seq = seq;
        let k = (seq % w) as usize;
        seq = seq.wrapping_add(1);
        if work_tx[k].send(slot).await.is_err() {
            break;
        }

        // Drain the socket's already-queued datagrams (never wait).
        loop {
            let mut slot = match free_rx.try_recv() {
                Ok(s) => s,
                Err(_) => break, // no free buffer: let the writer catch up
            };
            match transport.try_recv_from(&mut slot.cipher) {
                Ok((n, addr)) => {
                    slot.cipher_len = n;
                    slot.addr = addr;
                    slot.seq = seq;
                    let k = (seq % w) as usize;
                    seq = seq.wrapping_add(1);
                    if work_tx[k].send(slot).await.is_err() {
                        return;
                    }
                }
                Err(_) => {
                    let _ = free_tx.try_send(slot);
                    break;
                }
            }
        }
    }
    debug!("decrypt pool reader stopped");
}

/// Decrypts one slot at a time. Data packets are decrypted straight into the
/// slot's `plain` buffer; keepalives are answered inline; handshakes are
/// forwarded out of band. Every slot (including skipped ones) is passed to the
/// writer to keep the writer's rotation count in lockstep with `seq`.
async fn worker<T: Transport>(
    mut work_rx: mpsc::Receiver<Box<Slot>>,
    done_tx: mpsc::Sender<Box<Slot>>,
    transport: Arc<T>,
    sessions: Sessions,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    inf_sessions_timeout: bool,
    seg: usize,
) {
    // Per-worker 1-entry session cache: a hot single flow hits it every packet,
    // skipping the DashMap lookup entirely.
    let mut cached: Option<(SessionId, Arc<Session>)> = None;
    let mut encode_buf = [0u8; 65600]; // keepalive response scratch

    while let Some(mut slot) = work_rx.recv().await {
        slot.action = SlotAction::Skip;
        slot.session = None;

        if slot.cipher_len == 0 || slot.cipher_len >= slot.cipher.len() {
            warn!("dropping datagram from {} (size {})", slot.addr, slot.cipher_len);
            if done_tx.send(slot).await.is_err() {
                break;
            }
            continue;
        }

        match PacketRef::from_bytes(&slot.cipher[..slot.cipher_len]) {
            None => warn!("failed to parse packet from {}", slot.addr),

            Some(PacketRef::DataClient { sid, nonce, ciphertext }) => {
                let session = match &cached {
                    Some((cs, s)) if *cs == sid => Some(s.clone()),
                    _ => match sessions.get_by_sid(&sid) {
                        Some(s) => {
                            cached = Some((sid, s.clone()));
                            Some(s)
                        }
                        None => {
                            warn!("[{}] data for unknown session {}", slot.addr, sid);
                            None
                        }
                    },
                };

                if let Some(session) = session {
                    if !inf_sessions_timeout {
                        session.last_seen.store(sec_since_start(), Ordering::Relaxed);
                    }
                    // Decrypt into the slot's plain buffer at the reserved offset.
                    slot.plain.resize(seg, 0);
                    let base = slot.plain.as_ptr() as usize;
                    let dec = noise_decrypt_data_client_into(
                        ciphertext,
                        &session.state,
                        &mut slot.plain[TUN_SEND_OFFSET..],
                        nonce,
                    );
                    match dec {
                        Err(e) => warn!("[{}] decrypt failed (sid {}): {}", slot.addr, sid, e),
                        Ok(DataClientActionRef::Forward(packet)) => {
                            let start = packet.as_ptr() as usize - base;
                            let len = packet.len();
                            slot.plain.copy_within(start..start + len, TUN_SEND_OFFSET);
                            slot.plain.truncate(TUN_SEND_OFFSET + len);
                            if session.sock_addr() != slot.addr {
                                debug!("[{}] addr changed for sid {}", slot.addr, sid);
                                session.set_sock_addr(slot.addr);
                            }
                            slot.nonce = nonce;
                            slot.session = Some(session);
                            slot.action = SlotAction::Forward;
                        }
                        Ok(DataClientActionRef::KeepAlive(client_ts)) => {
                            if session.sock_addr() != slot.addr {
                                session.set_sock_addr(slot.addr);
                            }
                            let send_nonce = session.send_nonce.fetch_add(1, Ordering::Relaxed);
                            match noise_encrypt(
                                &DataServerBody::KeepAlive(client_ts),
                                &session.state,
                                send_nonce,
                            ) {
                                Err(e) => error!("[{}] keepalive encrypt failed: {}", slot.addr, e),
                                Ok(encrypted) => {
                                    let m = encode_data_server_frame(
                                        send_nonce,
                                        &encrypted,
                                        &mut encode_buf,
                                    );
                                    if let Err(e) =
                                        transport.send_to(&encode_buf[..m], &slot.addr).await
                                    {
                                        error!("[{}] keepalive send failed: {}", slot.addr, e);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Some(PacketRef::HandshakeInitial(hs_data)) => {
                let hs = hs_data.to_vec().into();
                if let Err(e) = handshake_tx.send((hs, slot.addr)).await {
                    error!("handshake_tx closed: {}", e);
                }
            }

            Some(_) => warn!("[{}] unexpected packet variant", slot.addr),
        }

        if done_tx.send(slot).await.is_err() {
            break;
        }
    }
    debug!("decrypt pool worker stopped");
}

/// Reassembles the decrypted stream in `seq` order by reading `done[expected %
/// workers]` in strict rotation, batches `Forward` packets, and flushes them to
/// the TUN in one GRO-merged `send_multiple`. The anti-replay check runs here,
/// single-threaded and in order.
async fn writer<N: Network>(
    mut stop: watch::Receiver<bool>,
    network: Arc<N>,
    workers: usize,
    mut done_rx: Vec<mpsc::Receiver<Box<Slot>>>,
    free_tx: mpsc::Sender<Box<Slot>>,
    seg: usize,
) {
    let w = workers as u64;
    let mut gro = GroState::new();
    // Contiguous batch handed to tun-rs; each entry gets a slot's plain buffer
    // swapped in on Forward.
    let mut batch: Vec<Vec<u8>> = (0..TUN_BATCH_SIZE).map(|_| vec![0u8; seg]).collect();
    // Slots whose buffers are currently swapped into `batch`, recycled on flush.
    // Boxed because they are returned to the freelist channel as `Box<Slot>`.
    #[allow(clippy::vec_box)]
    let mut in_batch: Vec<Box<Slot>> = Vec::with_capacity(TUN_BATCH_SIZE);
    let mut batch_len = 0usize;
    let mut expected: u64 = 0;

    loop {
        let k = (expected % w) as usize;

        // Non-blocking first, so a run of ready packets coalesces into one write.
        let slot = match done_rx[k].try_recv() {
            Ok(s) => s,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
            Err(mpsc::error::TryRecvError::Empty) => {
                // Nothing ready in order: flush what we have, then wait for it.
                if batch_len > 0 {
                    flush(&network, &mut gro, &mut batch, batch_len, &mut in_batch, &free_tx).await;
                    batch_len = 0;
                }
                tokio::select! {
                    _ = stop.changed() => break,
                    r = done_rx[k].recv() => match r { Some(s) => s, None => break },
                }
            }
        };
        expected = expected.wrapping_add(1);

        match slot.action {
            SlotAction::Forward => {
                let mut slot = slot;
                let ok = match &slot.session {
                    Some(session) => {
                        session.recv_window.lock().unwrap().check_and_update(slot.nonce)
                    }
                    None => false,
                };
                if ok {
                    std::mem::swap(&mut batch[batch_len], &mut slot.plain);
                    in_batch.push(slot);
                    batch_len += 1;
                    if batch_len == TUN_BATCH_SIZE {
                        flush(&network, &mut gro, &mut batch, batch_len, &mut in_batch, &free_tx)
                            .await;
                        batch_len = 0;
                    }
                } else {
                    warn!("replay/stale nonce {} dropped", slot.nonce);
                    let _ = free_tx.try_send(slot);
                }
            }
            SlotAction::Skip => {
                let _ = free_tx.try_send(slot);
            }
        }
    }

    if batch_len > 0 {
        flush(&network, &mut gro, &mut batch, batch_len, &mut in_batch, &free_tx).await;
    }
    debug!("decrypt pool writer stopped");
}

/// Write `batch[..batch_len]` to the TUN and recycle the slots that fed it.
#[allow(clippy::vec_box)] // slots are recycled back to the freelist as Box<Slot>
async fn flush<N: Network>(
    network: &Arc<N>,
    gro: &mut GroState,
    batch: &mut [Vec<u8>],
    batch_len: usize,
    in_batch: &mut Vec<Box<Slot>>,
    free_tx: &mpsc::Sender<Box<Slot>>,
) {
    if let Err(e) = network
        .send_multiple(gro, &mut batch[..batch_len], TUN_SEND_OFFSET)
        .await
    {
        error!("network send_multiple error: {}", e);
    }
    for slot in in_batch.drain(..) {
        let _ = free_tx.try_send(slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::network::{NetworkReceiver, NetworkSender};
    use crate::gateway::transport::TransportSender;
    use crate::gateway::transport::mock::MockTransport;
    use crate::protocol::Alg;
    use crate::runtime::crypto::{encode_data_client_packet, make_noise_pair_for_test};
    use std::io;

    /// Mock TUN that records every packet handed to it, in order. Only the send
    /// side is exercised by the receive pool (`send_multiple` → default → `send`).
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

    /// N distinct data packets pushed through the pool must arrive at the TUN in
    /// send order, none lost or duplicated, regardless of worker interleaving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_preserves_order_and_delivers_all() {
        const N: u64 = 500;
        const WORKERS: usize = 4;

        // Client encrypts with `init`; the session decrypts with `resp`.
        let (client_state, server_state) = make_noise_pair_for_test();

        let sessions = Sessions::new(&"10.0.0.0".parse().unwrap(), 8);
        let addr: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let sid = sessions.next_session_id().unwrap();
        let ip = sessions.next_holy_ip().unwrap();
        sessions.add(sid, ip, addr, Alg::ChaCha20Poly1305, server_state);

        let (client_tp, server_tp) = MockTransport::create_pair();
        let server_tp = Arc::new(server_tp);

        let (writes_tx, mut writes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let network = Arc::new(RecordingNetwork { writes: writes_tx, mtu: 1420 });

        let (handshake_tx, _handshake_rx) = mpsc::channel(16);
        let (_stop_tx, stop_rx) = watch::channel(false);

        let pool = tokio::spawn(recv_decrypt_forward_pool(
            stop_rx,
            server_tp.clone(),
            network,
            sessions,
            handshake_tx,
            true,
            WORKERS,
        ));

        // Each packet's payload starts with its sequence number, so we can check
        // the exact delivery order at the TUN.
        for seq in 0..N {
            let mut payload = vec![0u8; 64];
            payload[..8].copy_from_slice(&seq.to_le_bytes());
            let mut frame = vec![0u8; 65600];
            let n = encode_data_client_packet(&payload, sid, &client_state, seq, &mut frame).unwrap();
            client_tp.send_to(&frame[..n], &addr).await.unwrap();
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
