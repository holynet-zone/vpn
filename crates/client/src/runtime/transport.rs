#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "ws")]
pub mod ws;

use async_trait::async_trait;
use std::io;

#[async_trait]
pub trait TransportSender: Send + Sync {
    async fn send(&self, data: &[u8]) -> io::Result<usize>;
}

#[async_trait]
pub trait TransportReceiver: Send + Sync {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize>;
}

#[async_trait]
pub trait Transport: TransportSender + TransportReceiver + Send + Sync {
    async fn connect(&self) -> io::Result<()>;
}
