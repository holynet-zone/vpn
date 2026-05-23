use async_trait::async_trait;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tun_rs::AsyncDevice;

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
pub trait Network: NetworkSender + NetworkReceiver {}

pub struct TunNetwork(pub Arc<AsyncDevice>);

#[async_trait]
impl NetworkSender for TunNetwork {
    async fn send_to(&self, data: &[u8], _addr: &SocketAddr) -> io::Result<usize> {
        self.0.send(data).await
    }

    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.0.send(data).await
    }
}

#[async_trait]
impl NetworkReceiver for TunNetwork {
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let n = self.0.recv(buffer).await?;
        Ok((n, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
    }

    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buffer).await
    }
}

impl Network for TunNetwork {}
