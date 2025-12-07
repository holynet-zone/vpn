use crate::error::RuntimeError;
use crate::gateway::transport::{Transport, TransportReceiver, TransportSender};
use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use std::any::Any;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::info;

pub struct UdpTransport {
    socket: UdpSocket
}

impl UdpTransport {

    /// Create a new UDP transport with a pool of sockets (requires `udp-reuse-port` feature)
    /// Workers will share the same port using `SO_REUSEPORT` option
    ///
    /// Only available on Linux and some BSD systems
    #[cfg(feature = "udp-reuse-port")]
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

    /// Create a new UDP transport with single socket
    ///
    /// Available on all platforms
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
    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer).await
    }

    #[inline(always)]
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.socket.recv(buffer).await
    }
}

#[async_trait]
impl TransportSender for UdpTransport {
    #[inline(always)]
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(data, addr).await
    }

    #[inline(always)]
    async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        self.socket.send(data).await
    }
}

#[async_trait]
impl Transport for UdpTransport{
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn connect(&self) -> std::io::Result<()> {
        info!("connecting to udp://{}", self.socket.peer_addr()?);
        tokio::select! {
            _ = self.socket.connect(self.socket.peer_addr()?) => Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(5)) => Err(std::io::Error::other("connection timeout"))
        }
    }
}
