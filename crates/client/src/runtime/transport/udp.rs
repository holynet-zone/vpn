use crate::runtime::error::RuntimeError;
use crate::runtime::transport::{Transport, TransportReceiver, TransportSender};
use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

pub struct UdpTransport {
    socket: UdpSocket
}

impl UdpTransport {
    pub fn new(
        addr: SocketAddr, 
        so_rcvbuf: usize, 
        so_sndbuf: usize,
    ) -> Result<Self, RuntimeError> {
        let socket = Socket::new(
            Domain::for_address(addr),
            Type::DGRAM,
            Some(Protocol::UDP)
        )?;
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(so_rcvbuf)?;
        socket.set_send_buffer_size(so_sndbuf)?;
        socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0).into())?;
        socket.connect(&addr.into())?;
        
        Ok(Self { socket: UdpSocket::from_std(socket.into())? })
    }
}

#[async_trait]
impl TransportReceiver for UdpTransport {

    #[inline(always)]
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.socket.recv(buffer).await
    }
}

#[async_trait]
impl TransportSender for UdpTransport {
    #[inline(always)]
    async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        self.socket.send(data).await
    }
}

impl Transport for UdpTransport{}
