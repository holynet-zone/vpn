pub mod udp;

use std::io;
use std::net::SocketAddr;
use async_trait::async_trait;

#[async_trait]
pub trait TransportSender: Send + Sync {
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> io::Result<usize>;
}

#[async_trait]
pub trait TransportReceiver: Send + Sync {
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

pub trait Transport: TransportSender + TransportReceiver{}