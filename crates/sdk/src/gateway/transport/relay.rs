//! Client transport that tunnels through a chain of transparent relays.
//!
//! Wraps a single inner [`ClientTransport`] connected to the first relay node and
//! carries an end-to-end session with the final destination. Rather than nesting
//! one wrapper type per hop (which the non-dyn-compatible transport traits cannot
//! express at runtime-variable depth), it holds the ordered destination keys in a
//! `Vec` and applies N `RelayData` layers over that one socket. Depth is therefore
//! a runtime value with no bound, and the hot path stays monomorphic and
//! allocation-free.
//!
//! ```text
//! dests = [R2, R3, ..., server]     (inner socket dials R1)
//! send : [RD id0][RD id1]...[RD idn][ payload ]   one datagram, ids[0] outermost
//! R1 strips id0 -> R2 strips id1 -> ... -> server gets the inner frame
//! ```
//!
//! Every relay sees only ciphertext (the inner frame is the client's Noise
//! session with the final node), and each relay learns only its own layer's
//! previous and next hop, never the full path.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::crypto::PublicKey;
use crate::gateway::transport::{ClientTransport, Transport, TransportReceiver, TransportSender};
use crate::protocol::PacketRef;
use crate::runtime::crypto::{RELAY_DATA_HDR_LEN, TYPE_RELAY_DATA, relay_open_frame};

pub struct RelayChain<T: ClientTransport> {
    inner: Arc<T>,
    /// Ordered relay destinations: `dests[0]` is opened at the dialed node,
    /// `dests[last]` is the final end-to-end peer. One `RelayData` layer per entry.
    dests: Vec<PublicKey>,
    open_timeout: Duration,
    /// Per-layer relay ids, filled during `connect`. `relay_ids[0]` is outermost.
    relay_ids: Vec<AtomicU32>,
}

impl<T: ClientTransport> RelayChain<T> {
    /// `dests` must be non-empty and ordered from the first relay's target to the
    /// final end-to-end peer.
    pub fn new(inner: Arc<T>, dests: Vec<PublicKey>, open_timeout: Duration) -> Self {
        let relay_ids = dests.iter().map(|_| AtomicU32::new(0)).collect();
        Self {
            inner,
            dests,
            open_timeout,
            relay_ids,
        }
    }

    fn layers(&self) -> usize {
        self.dests.len()
    }

    /// Prepend `layers` `RelayData` headers (ids[0] outermost) then `payload`,
    /// writing into `out`. Returns the total length.
    fn wrap(&self, out: &mut [u8], payload: &[u8], layers: usize) -> usize {
        let hdr_total = layers * RELAY_DATA_HDR_LEN;
        for i in 0..layers {
            let id = self.relay_ids[i].load(Ordering::Relaxed);
            let off = i * RELAY_DATA_HDR_LEN;
            out[off] = TYPE_RELAY_DATA;
            out[off + 1..off + RELAY_DATA_HDR_LEN].copy_from_slice(&id.to_be_bytes());
        }
        out[hdr_total..hdr_total + payload.len()].copy_from_slice(payload);
        hdr_total + payload.len()
    }

    /// Verify `layers` leading `RelayData` headers match our ids in order and
    /// return the payload offset, or `None` for a stray/mismatched frame.
    fn strip(&self, buf: &[u8], layers: usize) -> Option<usize> {
        let hdr_total = layers * RELAY_DATA_HDR_LEN;
        if buf.len() < hdr_total {
            return None;
        }
        for i in 0..layers {
            let off = i * RELAY_DATA_HDR_LEN;
            if buf[off] != TYPE_RELAY_DATA {
                return None;
            }
            let id = u32::from_be_bytes([buf[off + 1], buf[off + 2], buf[off + 3], buf[off + 4]]);
            if id != self.relay_ids[i].load(Ordering::Relaxed) {
                return None;
            }
        }
        Some(hdr_total)
    }
}

impl<T: ClientTransport> TransportSender for RelayChain<T> {
    fn send<'a>(&'a self, data: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            let layers = self.layers();
            // Stack scratch (no per-packet heap alloc); one UDP datagram never
            // exceeds this. Oversized input is rejected rather than truncated.
            let mut frame = [0u8; 65600];
            if layers * RELAY_DATA_HDR_LEN + data.len() > frame.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "relay frame too large",
                ));
            }
            let n = self.wrap(&mut frame, data, layers);
            self.inner.send(&frame[..n]).await?;
            Ok(data.len())
        }
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        _addr: &'a SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        // The relay leg is a connected socket to the first relay; the destination
        // is fixed by the relay ids, so `addr` is irrelevant here.
        self.send(data)
    }

    /// Batch the client->relay leg: wrap each segment in all `layers` `RelayData`
    /// headers and send the run as one GSO `sendmsg` on the inner socket. The
    /// wrapped segments stay uniform (`segment_size + layers*hdr`, last may be
    /// smaller), so each on-wire datagram is a valid frame the first relay strips.
    fn send_gso<'a>(
        &'a self,
        buf: &'a [u8],
        segment_size: usize,
        _addr: Option<&'a SocketAddr>,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            if segment_size == 0 || buf.is_empty() {
                return Ok(0);
            }
            let layers = self.layers();
            let hdr_total = layers * RELAY_DATA_HDR_LEN;
            let wseg = segment_size + hdr_total;
            // Group so each wrapped GSO batch stays within the kernel limits
            // (<=64 segments and <=65535 bytes).
            let max_segs = (65535 / wseg).clamp(1, 64);
            let group_bytes = segment_size * max_segs;
            let mut scratch: Vec<u8> = Vec::new();
            let mut off = 0;
            while off < buf.len() {
                let end = (off + group_bytes).min(buf.len());
                let group = &buf[off..end];
                scratch.clear();
                let mut so = 0;
                while so < group.len() {
                    let se = (so + segment_size).min(group.len());
                    let base = scratch.len();
                    scratch.resize(base + hdr_total + (se - so), 0);
                    self.wrap(&mut scratch[base..], &group[so..se], layers);
                    so = se;
                }
                self.inner.send_gso(&scratch, wseg, None).await?;
                off = end;
            }
            Ok(buf.len())
        }
    }
}

impl<T: ClientTransport> TransportReceiver for RelayChain<T> {
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            let layers = self.layers();
            loop {
                let n = self.inner.recv(buffer).await?;
                // Strip all layers in place; ignore stray/mismatched frames.
                if let Some(off) = self.strip(&buffer[..n], layers) {
                    buffer.copy_within(off..n, 0);
                    return Ok(n - off);
                }
            }
        }
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a {
        async move {
            let n = self.recv(buffer).await?;
            Ok((n, SocketAddr::from(([0, 0, 0, 0], 0))))
        }
    }
}

impl<T: ClientTransport> Transport for RelayChain<T> {}

impl<T: ClientTransport> ClientTransport for RelayChain<T> {
    fn connect<'a>(&'a self) -> impl Future<Output = io::Result<()>> + Send + 'a {
        async move {
            self.inner.connect().await?;
            let m = self.layers();
            // Open each relay in turn, tunnelling the RelayOpen for hop k through
            // the k already-open outer layers. The reply comes back wrapped in the
            // same k layers.
            let mut recv_buf = vec![0u8; m * RELAY_DATA_HDR_LEN + 64];
            let mut send_buf = vec![0u8; m * RELAY_DATA_HDR_LEN + relay_open_frame(&[0u8; 32]).len()];
            for k in 0..m {
                let open = relay_open_frame(self.dests[k].as_bytes());
                let n = self.wrap(&mut send_buf, &open, k);
                self.inner.send(&send_buf[..n]).await?;

                let fut = async {
                    loop {
                        let rn = self.inner.recv(&mut recv_buf).await?;
                        if let Some(off) = self.strip(&recv_buf[..rn], k)
                            && let Some(PacketRef::RelayOpened(id)) =
                                PacketRef::from_bytes(&recv_buf[off..rn])
                        {
                            return Ok::<u32, io::Error>(id);
                        }
                    }
                };
                let id = tokio::time::timeout(self.open_timeout, fut)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay open timeout"))??;
                if id == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "relay refused (unknown destination or capacity)",
                    ));
                }
                self.relay_ids[k].store(id, Ordering::Relaxed);
            }
            Ok(())
        }
    }
}
