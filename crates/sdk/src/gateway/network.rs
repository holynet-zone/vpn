use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tun_rs::AsyncDevice;

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

pub trait Network: NetworkSender + NetworkReceiver {}

pub struct TunNetwork(pub Arc<AsyncDevice>);

impl NetworkSender for TunNetwork {
    async fn send_to(&self, data: &[u8], _addr: &SocketAddr) -> io::Result<usize> {
        self.0.send(data).await
    }

    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.0.send(data).await
    }
}

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
