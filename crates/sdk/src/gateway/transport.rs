#[cfg(feature = "udp")]
pub mod udp;
#[cfg(all(target_os = "linux", feature = "udp-uring"))]
pub mod uring;

#[cfg(test)]
mod mock;
#[cfg(feature = "ws")]
pub mod ws;

use std::future::Future;
use std::io;
use std::net::SocketAddr;

/// Send half — implemented by both server and client transports.
pub trait TransportSender: Send + Sync {
    fn send_to<'a>(&'a self, data: &'a [u8], addr: &'a SocketAddr) -> impl Future<Output = io::Result<usize>> + Send + 'a;
    fn send<'a>(&'a self, data: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

/// Receive half — implemented by both server and client transports.
pub trait TransportReceiver: Send + Sync {
    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a;
    fn recv<'a>(&'a self, buffer: &'a mut [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

/// Base transport — shared by server and client.
/// Does not include `connect()`, which is client-specific.
pub trait Transport: TransportSender + TransportReceiver {}

/// Client-side transport — extends `Transport` with connection setup.
/// Only client transports (`UdpTransport::new`, `WsClientTransport`) implement this.
pub trait ClientTransport: Transport {
    fn connect<'a>(&'a self) -> impl Future<Output = io::Result<()>> + Send + 'a;
}
