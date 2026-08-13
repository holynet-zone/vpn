#[cfg(feature = "udp")]
pub mod udp;

#[cfg(test)]
mod mock;
#[cfg(feature = "ws")]
pub mod ws;

use std::future::Future;
use std::io;
use std::net::SocketAddr;

/// Send half — implemented by both server and client transports.
pub trait TransportSender: Send + Sync {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        addr: &'a SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;
    fn send<'a>(&'a self, data: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;

    /// Send `buf` as consecutive UDP datagrams of `segment_size` bytes each (the
    /// last may be smaller) in a single syscall via UDP GSO (`UDP_SEGMENT`).
    ///
    /// `addr` is `Some(_)` for unconnected sockets (server side) and `None` for
    /// connected ones (client side). All segments go to the same destination.
    ///
    /// Default impl performs **no** GSO — it splits `buf` and sends each segment
    /// individually, so non-UDP transports and non-Linux targets stay correct.
    fn send_gso<'a>(
        &'a self,
        buf: &'a [u8],
        segment_size: usize,
        addr: Option<&'a SocketAddr>,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            if segment_size == 0 {
                return Ok(0);
            }
            let mut off = 0;
            while off < buf.len() {
                let end = (off + segment_size).min(buf.len());
                match addr {
                    Some(a) => self.send_to(&buf[off..end], a).await?,
                    None => self.send(&buf[off..end]).await?,
                };
                off = end;
            }
            Ok(buf.len())
        }
    }

    /// Send a run of equal-`segment_size` frames via UDP GSO, chunked to respect
    /// kernel limits: at most 64 segments and 65535 bytes per `sendmsg`. All
    /// frames must be `segment_size` bytes except possibly the very last.
    fn send_gso_chunked<'a>(
        &'a self,
        buf: &'a [u8],
        segment_size: usize,
        addr: Option<&'a SocketAddr>,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            if segment_size == 0 {
                return Ok(0);
            }
            let max_segs = (65535 / segment_size).clamp(1, 64);
            let chunk = segment_size * max_segs;
            let mut off = 0;
            while off < buf.len() {
                let end = (off + chunk).min(buf.len());
                self.send_gso(&buf[off..end], segment_size, addr).await?;
                off = end;
            }
            Ok(buf.len())
        }
    }
}

/// Receive half — implemented by both server and client transports.
pub trait TransportReceiver: Send + Sync {
    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a;
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;

    /// Non-blocking drain of an already-queued datagram. Returns `WouldBlock`
    /// when the socket buffer is empty. Used to opportunistically gather a batch
    /// of pending datagrams for a single batched TUN write, without ever waiting
    /// (so no latency is added to a single-packet flow).
    ///
    /// Default: not supported (returns `WouldBlock`), disabling drain-batching.
    fn try_recv_from(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "try_recv_from unsupported"))
    }

    /// Connected-socket variant of [`Self::try_recv_from`].
    fn try_recv(&self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "try_recv unsupported"))
    }
}

/// Base transport — shared by server and client.
/// Does not include `connect()`, which is client-specific.
pub trait Transport: TransportSender + TransportReceiver {}

/// Client-side transport — extends `Transport` with connection setup.
/// Only client transports (`UdpTransport::new`, `WsClientTransport`) implement this.
pub trait ClientTransport: Transport {
    fn connect<'a>(&'a self) -> impl Future<Output = io::Result<()>> + Send + 'a;
}
