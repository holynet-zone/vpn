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
