#[cfg(feature = "udp")]
pub mod udp;

#[cfg(feature = "ws")]
pub mod ws;
mod mock;

use std::io;
use std::net::SocketAddr;
use async_trait::async_trait;

/// Send half — implemented by both server and client transports.
#[async_trait]
pub trait TransportSender: Send + Sync {
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> io::Result<usize>;
    async fn send(&self, data: &[u8]) -> io::Result<usize>;
}

/// Receive half — implemented by both server and client transports.
#[async_trait]
pub trait TransportReceiver: Send + Sync {
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize>;
}

/// Base transport — shared by server and client.
/// Does not include `connect()`, which is client-specific.
pub trait Transport: TransportSender + TransportReceiver {}

/// Client-side transport — extends `Transport` with connection setup.
/// Only client transports (`UdpTransport::new`, `WsClientTransport`) implement this.
#[async_trait]
pub trait ClientTransport: Transport {
    async fn connect(&self) -> io::Result<()>;
}
