//! Parallel encrypt pipeline (WireGuard-style) for the client send path.
//!
//! Mirror of the server's [`recv_pool`](crate::runtime::server) on the transmit
//! side. The single [`encrypt_forward`](super::network::encrypt_forward) task
//! reads the TUN, encrypts, and sends all on one core, so a bulk upload is
//! capped by one core's AEAD + syscall budget. This spreads the encryption
//! across a worker pool while emitting datagrams on the wire in nonce order:
//!
//! ```text
//!   reader ──seq 0,1,2…──▶ worker[seq % W] ──▶ sender (reads done[expected % W]
//!   (TUN recv_multiple,     (W tasks encrypt   in rotation → nonce order on the
//!    assign seq + nonce)     in parallel)       wire) ──▶ UDP GSO send
//! ```
//!
//! On-wire order matters: the server restores *receive* order, so if the client
//! shuffled datagrams the server would faithfully reproduce the shuffle onto its
//! TUN. The rotation-ordered sender guarantees the wire order equals the nonce
//! order the reader assigned. Zero-copy hand-off via a recycled slot freelist;
//! the only added copy is the sender gathering frames into one GSO buffer.

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, warn};

use crate::gateway::network::{Network, TUN_BATCH_SIZE};
use crate::gateway::transport::ClientTransport;
use crate::protocol::SessionId;
use crate::runtime::client::AWAIT_STATE_DELAY;
use crate::runtime::crypto::encode_data_client_packet;
use crate::runtime::error::RuntimeError;
use crate::runtime::state::{ClientSession, RuntimeState};

/// In-flight slots per worker.
const SLOTS_PER_WORKER: usize = 8;
/// Depth of each `reader → worker` and `worker → sender` channel.
const CHAN_CAP: usize = 4;

/// One recyclable unit travelling reader → worker → sender → free.
struct Slot {
    seq: u64,
    /// Raw IP packet read from the TUN (`[..ip_len]` valid).
    ip: Vec<u8>,
    ip_len: usize,
    nonce: u64,
    sid: SessionId,
    session: Option<ClientSession>,
    /// Encoded `DataClient` datagram (`[..out_len]`), filled by the worker.
    out: Vec<u8>,
    out_len: usize,
    /// Whether `out` holds a datagram to send (false = dropped/empty/error).
    ok: bool,
}

impl Slot {
    fn new(cap: usize) -> Self {
        Self {
            seq: 0,
            ip: vec![0u8; cap],
            ip_len: 0,
            nonce: 0,
            sid: SessionId::default(),
            session: None,
            out: vec![0u8; cap + 64],
            out_len: 0,
            ok: false,
        }
    }
}

/// Spawn the TUN reader + `workers` encrypt tasks + ordered sender.
pub(super) async fn encrypt_forward_pool<T: ClientTransport + 'static, N: Network + 'static>(
    state_tx: watch::Sender<RuntimeState>,
    network: Arc<N>,
    transport: Arc<T>,
    workers: usize,
) {
    let mtu = network.mtu() as usize;
    let cap = mtu + 128;
    let slots_total = (workers * SLOTS_PER_WORKER).max(2 * TUN_BATCH_SIZE);

    let (free_tx, free_rx) = mpsc::channel::<Box<Slot>>(slots_total);
    for _ in 0..slots_total {
        free_tx
            .try_send(Box::new(Slot::new(cap)))
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
        set.spawn(worker(wrx, dtx, state_tx.clone()));
    }

    set.spawn(reader(
        state_tx.clone(),
        network.clone(),
        workers,
        free_rx,
        free_tx.clone(),
        work_tx,
    ));
    set.spawn(sender(
        state_tx.clone(),
        transport.clone(),
        network.mtu(),
        workers,
        done_rx,
        free_tx.clone(),
    ));
    drop(free_tx);

    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            error!("encrypt pool task failed: {}", e);
        }
    }
    debug!("encrypt_forward_pool stopped");
}

/// Owns the TUN. Reads batches, tags each packet with a monotonic `seq` and a
/// fresh session nonce (in order), and round-robins to `work[seq % workers]`.
async fn reader<N: Network>(
    state_tx: watch::Sender<RuntimeState>,
    network: Arc<N>,
    workers: usize,
    mut free_rx: mpsc::Receiver<Box<Slot>>,
    free_tx: mpsc::Sender<Box<Slot>>,
    work_tx: Vec<mpsc::Sender<Box<Slot>>>,
) {
    let w = workers as u64;
    let mut seq: u64 = 0;

    let mut state_rx = state_tx.subscribe();
    let mut orig = vec![0u8; 10 + 65535];
    let mut bufs: Vec<Vec<u8>> =
        (0..TUN_BATCH_SIZE).map(|_| vec![0u8; network.mtu() as usize + 128]).collect();
    let mut sizes = vec![0usize; TUN_BATCH_SIZE];
    let mut state_wait_timer = tokio::time::interval(AWAIT_STATE_DELAY);

    let mut is_connected = false;
    let mut sid = SessionId::default();
    let mut session: Option<ClientSession> = None;

    'main: loop {
        if !is_connected {
            match state_rx.has_changed() {
                Ok(false) => {
                    state_wait_timer.tick().await;
                    continue;
                }
                Err(_) => break,
                Ok(true) => {}
            }
        }

        tokio::select! {
            _ = state_rx.changed() => {
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    RuntimeState::Connecting => {
                        is_connected = false;
                        session = None;
                    }
                    RuntimeState::Connected((payload, s)) => {
                        sid = payload.sid;
                        session = Some(s.clone());
                        is_connected = true;
                    }
                    _ => {}
                }
            }
            result = network.recv_multiple(&mut orig, &mut bufs, &mut sizes, 0) => match result {
                Err(e) => {
                    let st = RuntimeState::Error(RuntimeError::IO(
                        format!("failed to receive from network: {}", e)
                    ));
                    if state_tx.send(st).is_err() { break; }
                }
                Ok(count) => {
                    let Some(ref sess) = session else {
                        warn!("received network packet before connected state, dropping");
                        continue;
                    };
                    for i in 0..count {
                        if sizes[i] == 0 {
                            continue;
                        }
                        let mut slot = tokio::select! {
                            _ = state_rx.changed() => {
                                // Re-evaluate connection state on the next loop.
                                continue 'main;
                            }
                            s = free_rx.recv() => match s { Some(s) => s, None => break 'main },
                        };
                        std::mem::swap(&mut slot.ip, &mut bufs[i]);
                        slot.ip_len = sizes[i];
                        slot.sid = sid;
                        slot.nonce = sess.send_nonce.fetch_add(1, Ordering::Relaxed);
                        slot.session = Some(sess.clone());
                        slot.ok = false;
                        slot.seq = seq;
                        let k = (seq % w) as usize;
                        seq = seq.wrapping_add(1);
                        if work_tx[k].send(slot).await.is_err() {
                            break 'main;
                        }
                    }
                }
            }
        }
    }
    let _ = free_tx;
    debug!("encrypt pool reader stopped");
}

/// Encrypts one packet at a time into the slot's `out` buffer.
async fn worker(
    mut work_rx: mpsc::Receiver<Box<Slot>>,
    done_tx: mpsc::Sender<Box<Slot>>,
    state_tx: watch::Sender<RuntimeState>,
) {
    while let Some(mut slot) = work_rx.recv().await {
        slot.ok = false;
        if let Some(session) = slot.session.clone() {
            let ip_len = slot.ip_len;
            let nonce = slot.nonce;
            let sid = slot.sid;
            // Split the borrow: read `ip`, write `out`.
            let (ip, out) = {
                let s = &mut *slot;
                (&s.ip[..ip_len], &mut s.out)
            };
            match encode_data_client_packet(ip, sid, &session.noise, nonce, out) {
                Ok(n) => {
                    slot.out_len = n;
                    slot.ok = true;
                }
                Err(e) => {
                    let _ = state_tx.send(RuntimeState::Error(RuntimeError::Unexpected(
                        format!("failed to encrypt data: {}", e),
                    )));
                }
            }
        }
        if done_tx.send(slot).await.is_err() {
            break;
        }
    }
    debug!("encrypt pool worker stopped");
}

/// Emits datagrams in `seq` order by reading `done[expected % workers]` in
/// rotation, gathering a contiguous run into one GSO buffer, and sending it.
async fn sender<T: ClientTransport>(
    state_tx: watch::Sender<RuntimeState>,
    transport: Arc<T>,
    mtu: u16,
    workers: usize,
    mut done_rx: Vec<mpsc::Receiver<Box<Slot>>>,
    free_tx: mpsc::Sender<Box<Slot>>,
) {
    let w = workers as u64;
    let mut state_rx = state_tx.subscribe();
    let mut gso_buf = vec![0u8; TUN_BATCH_SIZE * (mtu as usize + 64)];
    let mut frames: Vec<(usize, usize)> = Vec::with_capacity(TUN_BATCH_SIZE);
    #[allow(clippy::vec_box)] // slots are recycled to the freelist as Box<Slot>
    let mut pending: Vec<Box<Slot>> = Vec::with_capacity(TUN_BATCH_SIZE);
    let mut off = 0usize;
    let mut expected: u64 = 0;

    loop {
        let k = (expected % w) as usize;

        let slot = match done_rx[k].try_recv() {
            Ok(s) => s,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
            Err(mpsc::error::TryRecvError::Empty) => {
                if !frames.is_empty() {
                    flush(&transport, &state_tx, &gso_buf, &frames, &mut pending, &free_tx).await;
                    frames.clear();
                    off = 0;
                }
                tokio::select! {
                    _ = state_rx.changed() => {
                        if matches!(state_rx.borrow().deref(), RuntimeState::Error(_)) { break; }
                        continue;
                    }
                    r = done_rx[k].recv() => match r { Some(s) => s, None => break },
                }
            }
        };
        expected = expected.wrapping_add(1);

        if slot.ok {
            let n = slot.out_len;
            gso_buf[off..off + n].copy_from_slice(&slot.out[..n]);
            frames.push((off, n));
            off += n;
            pending.push(slot);
            if frames.len() == TUN_BATCH_SIZE {
                flush(&transport, &state_tx, &gso_buf, &frames, &mut pending, &free_tx).await;
                frames.clear();
                off = 0;
            }
        } else {
            let _ = free_tx.try_send(slot);
        }
    }
    debug!("encrypt pool sender stopped");
}

/// Send one batch (GSO-uniform run as a chunked `sendmsg`, else per-frame) and
/// recycle the slots that fed it.
#[allow(clippy::vec_box)] // slots are recycled to the freelist as Box<Slot>
async fn flush<T: ClientTransport>(
    transport: &Arc<T>,
    state_tx: &watch::Sender<RuntimeState>,
    gso_buf: &[u8],
    frames: &[(usize, usize)],
    pending: &mut Vec<Box<Slot>>,
    free_tx: &mpsc::Sender<Box<Slot>>,
) {
    if let Err(e) = send_batch(transport.as_ref(), gso_buf, frames).await {
        warn!("transport send error, reconnecting: {}", e);
        let _ = state_tx.send(RuntimeState::Connecting);
    }
    for slot in pending.drain(..) {
        let _ = free_tx.try_send(slot);
    }
}

/// Send a batch of contiguous frames. A GSO-uniform run (all but the last equal
/// to the first segment size, last no larger) goes out as one chunked `sendmsg`;
/// otherwise each frame is sent individually.
async fn send_batch<T: ClientTransport>(
    transport: &T,
    gso_buf: &[u8],
    frames: &[(usize, usize)],
) -> std::io::Result<()> {
    let Some(&(start, seg)) = frames.first() else {
        return Ok(());
    };
    let last = frames.len() - 1;
    let uniform = frames[..last].iter().all(|&(_, l)| l == seg) && frames[last].1 <= seg;
    if uniform {
        let (o, l) = frames[last];
        transport.send_gso_chunked(&gso_buf[start..o + l], seg, None).await?;
    } else {
        for &(o, l) in frames {
            transport.send(&gso_buf[o..o + l]).await?;
        }
    }
    Ok(())
}
