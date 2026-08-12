pub mod tun;

use std::future::Future;
use std::io;
use std::net::SocketAddr;

/// Maximum packets processed per batched TUN read/write.
///
/// On Linux this mirrors tun-rs' `IDEAL_BATCH_SIZE` (128) so a single 64 KiB
/// GSO super-frame splits into enough MTU-sized segments. On other platforms
/// there is no offload path, so the batch degenerates to a single packet.
#[cfg(target_os = "linux")]
pub const TUN_BATCH_SIZE: usize = tun_rs::IDEAL_BATCH_SIZE;
#[cfg(not(target_os = "linux"))]
pub const TUN_BATCH_SIZE: usize = 1;

/// Byte offset reserved at the front of each TUN-write buffer for the
/// `virtio_net_hdr` that tun-rs prepends when GRO-merging. Using this offset
/// keeps both the offload and the per-packet fallback paths writing the packet
/// payload at the same position, so the datapath needs no `if offload` branch.
#[cfg(target_os = "linux")]
pub const TUN_SEND_OFFSET: usize = tun_rs::VIRTIO_NET_HDR_LEN;
#[cfg(not(target_os = "linux"))]
pub const TUN_SEND_OFFSET: usize = 0;

/// Per-task GRO helper state for batched TUN writes.
///
/// Reused across `send_multiple` calls (tun-rs resets it internally each call),
/// so it allocates its internal flow tables only once per task. On non-Linux
/// platforms it is a zero-sized placeholder.
#[cfg(target_os = "linux")]
pub struct GroState(pub(crate) tun_rs::GROTable);
#[cfg(not(target_os = "linux"))]
pub struct GroState;

impl GroState {
    #[cfg(target_os = "linux")]
    pub fn new() -> Self {
        Self(tun_rs::GROTable::new())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Self {
        Self
    }
}

impl Default for GroState {
    fn default() -> Self {
        Self::new()
    }
}

pub trait NetworkSender: Send + Sync {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        addr: &'a SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;
    fn send<'a>(&'a self, data: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

pub trait NetworkReceiver: Send + Sync {
    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a;
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

pub trait Network: NetworkSender + NetworkReceiver {
    fn mtu(&self) -> u16;

    /// Whether kernel TUN GRO/TSO offload was requested for this device.
    /// Informational only — correctness of the batched methods does not depend
    /// on it (tun-rs falls back to per-packet transparently).
    fn offload_enabled(&self) -> bool {
        false
    }

    /// Read a batch of IP packets from the device.
    ///
    /// With offload active, one syscall returns a 64 KiB GSO super-frame that is
    /// split into up to `bufs.len()` MTU-sized packets (GRO on read). Each packet
    /// `i` is written to `bufs[i][offset..offset + sizes[i]]`; returns the count.
    /// `orig` is scratch space for the raw super-frame (recommend 10 + 65535).
    ///
    /// Default impl (no offload): a single `recv` into `bufs[0][offset..]`.
    fn recv_multiple<'a>(
        &'a self,
        _orig: &'a mut [u8],
        bufs: &'a mut [Vec<u8>],
        sizes: &'a mut [usize],
        offset: usize,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            let n = self.recv(&mut bufs[0][offset..]).await?;
            sizes[0] = n;
            Ok(1)
        }
    }

    /// Write a batch of IP packets to the device.
    ///
    /// Each buffer holds one packet payload at `buf[offset..]`. With offload
    /// active, tun-rs GRO-merges consecutive packets into fewer super-frames
    /// (prepending a `virtio_net_hdr` in the reserved `offset` bytes).
    ///
    /// Default impl (no offload): send each packet individually.
    fn send_multiple<'a>(
        &'a self,
        _gro: &'a mut GroState,
        bufs: &'a mut [Vec<u8>],
        offset: usize,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            let mut total = 0;
            for b in bufs.iter() {
                total += self.send(&b[offset..]).await?;
            }
            Ok(total)
        }
    }
}
