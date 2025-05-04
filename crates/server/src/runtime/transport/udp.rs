use std::any::Any;
use crate::runtime::error::RuntimeError;
use crate::runtime::transport::{Transport, TransportReceiver, TransportSender};
use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::info;

pub struct UdpTransport {
    socket: UdpSocket
}

impl UdpTransport {
    pub fn new_pool(
        addr: SocketAddr, 
        so_rcvbuf: usize, 
        so_sndbuf: usize, 
        count: usize
    ) -> Result<Vec<Self>, RuntimeError> {
        let socket = Socket::new(
            Domain::for_address(addr),
            Type::DGRAM,
            Some(Protocol::UDP)
        )?;

        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;
        socket.set_recv_buffer_size(so_rcvbuf)?;
        socket.set_send_buffer_size(so_sndbuf)?;
        socket.set_tos(0b101110 << 2)?;
        socket.bind(&addr.into())?;

        info!(
            "Runtime running on udp://{} with {} workers",
            addr,
            count
        );
        
        let mut sockets = Vec::with_capacity(count);
        for i in 0..count - 1 {
            let cloned_raw_socket = socket.try_clone().map_err(|err| {
                RuntimeError::IO(format!("clone socket #{}: {}", i + 1, err))
            })?.into();
            
            sockets.push(Self { socket: UdpSocket::from_std(cloned_raw_socket)? });
        }

        sockets.push(Self { socket: UdpSocket::from_std(socket.into())? });
        
        Ok(sockets)
    }
}

#[async_trait]
impl TransportReceiver for UdpTransport {

    #[inline(always)]
    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer).await
    }
}

#[async_trait]
impl TransportSender for UdpTransport {
    #[inline(always)]
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(data, addr).await
    }
}

impl Transport for UdpTransport{
    fn as_any(&self) -> &dyn Any {
        self
    }
}
