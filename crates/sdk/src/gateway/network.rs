pub mod tun;

use std::future::Future;
use std::io;
use std::net::SocketAddr;

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
}
