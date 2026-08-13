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
//!   reader ──batch 0,1,2,3…──▶ worker[batch % W] ──▶ writer (reads
//!   (one socket, one recvmmsg  (W tasks decrypt a    done[expected % W] in
//!    = one batch of up to       whole batch each)     strict rotation → global
//!    MMSG_BATCH datagrams)                            order restored) ──▶ TUN
//! ```
//!
//! ## Batch-granular handoffs (why a whole batch travels per channel message)
//!
//! Every `reader → worker` and `worker → writer` message is a whole [`Batch`] of
//! up to [`MMSG_BATCH`] datagrams, **not** one datagram. A per-datagram handoff
//! costs ~one task wakeup per packet (tokio work-stealing wakes the consumer on
//! another core: IPI + cache-miss, a few µs). At a few hundred k pps that alone
//! caps the pipeline's drain rate — with no core saturated — which is exactly
//! what capped this pool at ~3.3 Gbit/s. Carrying ~32 packets per message
//! amortises the wakeup ~32×, cutting the per-packet pipeline latency (and the
//! standing TCP queue it builds) roughly in half, the way wireguard-go passes
//! arrays of packets between its stages.
//!
//! ## Why the rotation restores order without a reorder buffer
//!
//! The reader assigns a strictly increasing batch `seq` and sends batch `seq` to
//! `work[seq % W]`. Each worker's channels are FIFO, so `done[k]` yields exactly
//! the sub-sequence of batches `k, k+W, k+2W, …` in increasing order. The writer
//! consumes `done[0], done[1], …, done[W-1], done[0], …`, i.e. batches
//! `0, 1, 2, …`; within each batch the datagrams keep their recvmmsg order (=
//! wire order). No per-packet reorder buffer, no sequence heap.
//!
//! ## Replay check lives in the writer
//!
//! The anti-replay window is checked in the single-threaded writer, in order —
//! never in the parallel workers. That keeps the per-session replay `Mutex`
//! uncontended (a hot single flow would otherwise have all W workers hammering
//! one lock every packet). A replayed datagram is still decrypted (wasted AEAD
//! work) but then dropped; replays are attack/dup-only and rare, so this matches
//! WireGuard-go's design.
//!
//! ## Zero-allocation steady state
//!
//! A fixed pool of [`Batch`] buffers circulates: `free → reader (recv into it) →
//! worker (decrypt) → writer (write to TUN) → free`. The writer swaps each
//! decrypted slot's buffer into its contiguous TUN batch (tun-rs wants `&mut
//! [Vec<u8>]`) and the swapped-out buffer rides back with the recycled batch, so
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

/// Datagrams the reader gathers per `recvmmsg` call and carries as one [`Batch`]
/// through the pipeline (<= transport's `MAX_MMSG`). This is the amortisation
/// unit: one channel message + one task wakeup covers up to this many packets.
const MMSG_BATCH: usize = 32;
/// Depth (in batches) of each `reader → worker` and `worker → writer` channel.
const CHAN_CAP: usize = 2;

/// What the writer should do with a processed slot.
#[derive(Clone, Copy)]
enum SlotAction {
    /// Decrypted IP packet sits in `plain[TUN_SEND_OFFSET..]`; write it to TUN
    /// after an in-order replay check.
    Forward,
    /// Nothing to write (parse/decrypt failure, replay, keepalive handled in the
    /// worker, or a handshake forwarded out of band). Just recycle the slot.
    Skip,
}

/// One datagram's worth of work inside a [`Batch`].
struct Slot {
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

/// A recyclable burst of up to [`MMSG_BATCH`] datagrams travelling
/// reader → worker → writer → free as a single unit. `slots[..len]` are valid.
struct Batch {
    /// Monotonic batch sequence; the writer consumes batches in `seq` order.
    seq: u64,
    len: usize,
    slots: Vec<Slot>,
}

impl Batch {
    fn new(cipher_cap: usize, seg: usize) -> Self {
        Self {
            seq: 0,
            len: 0,
            slots: (0..MMSG_BATCH).map(|_| Slot::new(cipher_cap, seg)).collect(),
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
    // Enough batches to keep every worker fed plus the channel depth on both
    // sides, so the reader rarely blocks on the freelist.
    let batches_total = (workers * (2 * CHAN_CAP + 2)).max(16);

    // Freelist, prefilled with every batch the pipeline owns.
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
        cipher_cap,
        free_rx,
        work_tx,
    ));
    set.spawn(writer(stop.clone(), network.clone(), workers, done_rx, free_tx.clone()));
    drop(free_tx);

    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            error!("decrypt pool task failed: {}", e);
        }
    }
    debug!("recv_decrypt_forward_pool stopped");
}

/// Owns the socket. Gathers a burst of datagrams per `recvmmsg` into one free
/// [`Batch`] (zero-copy: each received buffer is swapped into a slot), tags the
/// batch with a monotonic `seq`, and round-robins the whole batch to
/// `work[seq % workers]`. Batching both the receive syscall and the handoff is
/// what unblocks the pool.
async fn reader<T: Transport>(
    mut stop: watch::Receiver<bool>,
    transport: Arc<T>,
    workers: usize,
    cipher_cap: usize,
    mut free_rx: mpsc::Receiver<Box<Batch>>,
    work_tx: Vec<mpsc::Sender<Box<Batch>>>,
) {
    let w = workers as u64;
    let mut seq: u64 = 0;

    // Reusable receive scratch. Received data is swapped into a batch's slots
    // (O(1)), so these buffers and the slots just trade places — no per-packet
    // copy.
    let unspec = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    let mut rbufs: Vec<Vec<u8>> = (0..MMSG_BATCH).map(|_| vec![0u8; cipher_cap]).collect();
    let mut lens = vec![0usize; MMSG_BATCH];
    let mut addrs = vec![unspec; MMSG_BATCH];

    loop {
        let count = tokio::select! {
            _ = stop.changed() => break,
            r = transport.recv_mmsg(&mut rbufs, &mut lens, &mut addrs) => match r {
                Ok(0) => continue,
                Ok(c) => c,
                Err(e) => {
                    warn!("transport recv_mmsg error: {}", e);
                    continue;
                }
            }
        };

        // Grab a free batch. The data sits safely in `rbufs` until swapped, so
        // blocking here only applies backpressure.
        let mut batch = tokio::select! {
            _ = stop.changed() => return,
            b = free_rx.recv() => match b { Some(b) => b, None => return },
        };

        for i in 0..count {
            std::mem::swap(&mut batch.slots[i].cipher, &mut rbufs[i]);
            batch.slots[i].cipher_len = lens[i];
            batch.slots[i].addr = addrs[i];
        }
        batch.len = count;
        batch.seq = seq;
        let k = (seq % w) as usize;
        seq = seq.wrapping_add(1);
        if work_tx[k].send(batch).await.is_err() {
            return;
        }
    }
    debug!("decrypt pool reader stopped");
}

/// Decrypts every slot in each incoming batch, then forwards the whole batch to
/// the writer (skipped slots included, so the writer's rotation stays in lockstep
/// with the batch `seq`). Data packets decrypt straight into the slot's `plain`
/// buffer; keepalives are answered inline; handshakes go out of band.
async fn worker<T: Transport>(
    mut work_rx: mpsc::Receiver<Box<Batch>>,
    done_tx: mpsc::Sender<Box<Batch>>,
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

    while let Some(mut batch) = work_rx.recv().await {
        for si in 0..batch.len {
            decrypt_one(
                &mut batch.slots[si],
                &transport,
                &sessions,
                &handshake_tx,
                inf_sessions_timeout,
                seg,
                &mut cached,
                &mut encode_buf,
            )
            .await;
        }
        if done_tx.send(batch).await.is_err() {
            break;
        }
    }
    debug!("decrypt pool worker stopped");
}

/// Decrypt/dispatch a single slot in place, setting its `action` for the writer.
#[allow(clippy::too_many_arguments)]
async fn decrypt_one<T: Transport>(
    slot: &mut Slot,
    transport: &Arc<T>,
    sessions: &Sessions,
    handshake_tx: &mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    inf_sessions_timeout: bool,
    seg: usize,
    cached: &mut Option<(SessionId, Arc<Session>)>,
    encode_buf: &mut [u8],
) {
    slot.action = SlotAction::Skip;
    slot.session = None;

    if slot.cipher_len == 0 || slot.cipher_len >= slot.cipher.len() {
        warn!("dropping datagram from {} (size {})", slot.addr, slot.cipher_len);
        return;
    }

    match PacketRef::from_bytes(&slot.cipher[..slot.cipher_len]) {
        None => warn!("failed to parse packet from {}", slot.addr),

        Some(PacketRef::DataClient { sid, nonce, ciphertext }) => {
            let session = match &*cached {
                Some((cs, s)) if *cs == sid => Some(s.clone()),
                _ => match sessions.get_by_sid(&sid) {
                    Some(s) => {
                        *cached = Some((sid, s.clone()));
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
                                let m =
                                    encode_data_server_frame(send_nonce, &encrypted, encode_buf);
                                if let Err(e) = transport.send_to(&encode_buf[..m], &slot.addr).await
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
}

/// Reassembles the decrypted stream in batch `seq` order by reading `done[expected
/// % workers]` in strict rotation, batches `Forward` packets across incoming
/// batches, and flushes them to the TUN in one GRO-merged `send_multiple`. The
/// anti-replay check runs here, single-threaded and in order.
async fn writer<N: Network>(
    mut stop: watch::Receiver<bool>,
    network: Arc<N>,
    workers: usize,
    mut done_rx: Vec<mpsc::Receiver<Box<Batch>>>,
    free_tx: mpsc::Sender<Box<Batch>>,
) {
    let w = workers as u64;
    let mut gro = GroState::new();
    // Contiguous batch handed to tun-rs; each entry gets a slot's plain buffer
    // swapped in on Forward. Sized lazily from the first real batch's slot
    // capacity (all slots share the same seg), so we never hard-code it here.
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
                // Nothing ready in order: flush what we have, then wait for it.
                if tun_len > 0 {
                    flush(&network, &mut gro, &mut tun_batch, tun_len).await;
                    tun_len = 0;
                }
                tokio::select! {
                    _ = stop.changed() => break,
                    r = done_rx[k].recv() => match r { Some(b) => b, None => break },
                }
            }
        };
        expected = expected.wrapping_add(1);

        // Lazily size the TUN batch from the first real slot's buffer capacity.
        if tun_batch.is_empty() && batch.len > 0 {
            let cap = batch.slots[0].plain.capacity().max(1);
            tun_batch = (0..TUN_BATCH_SIZE).map(|_| vec![0u8; cap]).collect();
        }

        for si in 0..batch.len {
            match batch.slots[si].action {
                SlotAction::Forward => {
                    let ok = match &batch.slots[si].session {
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
                        warn!("replay/stale nonce {} dropped", batch.slots[si].nonce);
                    }
                }
                SlotAction::Skip => {}
            }
            // Drop the session Arc so a recycled batch doesn't pin sessions.
            batch.slots[si].session = None;
        }

        let _ = free_tx.try_send(batch);
    }

    if tun_len > 0 {
        flush(&network, &mut gro, &mut tun_batch, tun_len).await;
    }
    debug!("decrypt pool writer stopped");
}

/// Write `tun_batch[..len]` to the TUN in one GRO-merged `send_multiple`.
async fn flush<N: Network>(
    network: &Arc<N>,
    gro: &mut GroState,
    tun_batch: &mut [Vec<u8>],
    len: usize,
) {
    if let Err(e) = network
        .send_multiple(gro, &mut tun_batch[..len], TUN_SEND_OFFSET)
        .await
    {
        error!("network send_multiple error: {}", e);
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
