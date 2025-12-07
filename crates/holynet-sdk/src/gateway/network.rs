use std::io;
use std::net::SocketAddr;
use async_trait::async_trait;

#[async_trait]
pub trait NetworkSender: Send + Sync {
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> io::Result<usize>;
    async fn send(&self, data: &[u8]) -> io::Result<usize>;
}

#[async_trait]
pub trait NetworkReceiver: Send + Sync {
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize>;
}

#[async_trait]
pub trait Network: NetworkSender + NetworkReceiver{}
