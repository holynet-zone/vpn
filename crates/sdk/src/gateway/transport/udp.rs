use crate::gateway::transport::{ClientTransport, Transport, TransportReceiver, TransportSender};
use crate::runtime::error::RuntimeError;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::info;

pub struct UdpTransport {
    socket: UdpSocket,
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
        count: usize,
    ) -> Result<Vec<Self>, RuntimeError> {
        info!("Runtime running on udp://{} with {} workers", addr, count);

        // A real `SO_REUSEPORT` group: `count` independent sockets, each with its
        // own `socket()` + `SO_REUSEPORT` + `bind()`. The kernel then hashes the
        // 4-tuple and pins each flow to exactly one socket (=one worker), so a
        // single flow's datagrams are never split across workers and stay ordered.
        //
        // A previous version bound one socket and `try_clone()`d (`dup()`) it N
        // times — that is N descriptors onto ONE receive queue, so workers raced
        // `recv_from` on the same queue and reordered single-flow packets.
        let mut sockets = Vec::with_capacity(count);
        for i in 0..count {
            let socket =
                Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;

            socket.set_nonblocking(true)?;
            socket.set_reuse_port(true)?;
            socket.set_reuse_address(true)?;
            socket.set_recv_buffer_size(so_rcvbuf)?;
            socket.set_send_buffer_size(so_sndbuf)?;
            socket.set_tos_v4(0b101110 << 2)?;
            socket
                .bind(&addr.into())
                .map_err(|err| RuntimeError::IO(format!("bind socket #{}: {}", i, err)))?;

            sockets.push(Self {
                socket: UdpSocket::from_std(socket.into())?,
            });
        }

        Ok(sockets)
    }

    /// Create a new UDP transport with single socket
    ///
    /// Available on all platforms
    pub fn new(addr: SocketAddr, so_rcvbuf: usize, so_sndbuf: usize) -> Result<Self, RuntimeError> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(so_rcvbuf)?;
        socket.set_send_buffer_size(so_sndbuf)?;
        socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).into())?;
        socket.connect(&addr.into())?;

        Ok(Self {
            socket: UdpSocket::from_std(socket.into())?,
        })
    }
}

impl TransportReceiver for UdpTransport {
    #[inline(always)]
    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer).await
    }

    #[inline(always)]
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.socket.recv(buffer).await
    }

    #[inline(always)]
    fn try_recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.try_recv_from(buffer)
    }

    #[inline(always)]
    fn try_recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.socket.try_recv(buffer)
    }
}

impl TransportSender for UdpTransport {
    #[inline(always)]
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(data, addr).await
    }

    #[inline(always)]
    async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        self.socket.send(data).await
    }

    /// One `sendmsg` with a `UDP_SEGMENT` control message: the kernel slices
    /// `buf` into `segment_size`-byte datagrams. Falls back to a plain send when
    /// there is a single segment.
    #[cfg(target_os = "linux")]
    async fn send_gso(
        &self,
        buf: &[u8],
        segment_size: usize,
        addr: Option<&SocketAddr>,
    ) -> std::io::Result<usize> {
        use tokio::io::Interest;

        // Single datagram: skip the GSO cmsg entirely.
        if segment_size == 0 || buf.len() <= segment_size {
            return match addr {
                Some(a) => self.socket.send_to(buf, *a).await,
                None => self.socket.send(buf).await,
            };
        }

        let seg = segment_size.min(u16::MAX as usize) as u16;
        loop {
            self.socket.writable().await?;
            match self
                .socket
                .try_io(Interest::WRITABLE, || sendmsg_gso(&self.socket, buf, seg, addr))
            {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Perform a single non-blocking `sendmsg` carrying a `UDP_SEGMENT` cmsg.
#[cfg(target_os = "linux")]
fn sendmsg_gso(
    socket: &UdpSocket,
    buf: &[u8],
    seg: u16,
    addr: Option<&SocketAddr>,
) -> std::io::Result<usize> {
    use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
    use std::io::IoSlice;
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let iov = [IoSlice::new(buf)];
    let cmsgs = [ControlMessage::UdpGsoSegments(&seg)];
    let res = match addr {
        Some(a) => {
            let sa = SockaddrStorage::from(*a);
            sendmsg(fd, &iov, &cmsgs, MsgFlags::MSG_DONTWAIT, Some(&sa))
        }
        None => sendmsg::<SockaddrStorage>(fd, &iov, &cmsgs, MsgFlags::MSG_DONTWAIT, None),
    };
    res.map_err(|e| std::io::Error::from_raw_os_error(e as i32))
}

impl Transport for UdpTransport {}

impl ClientTransport for UdpTransport {
    async fn connect(&self) -> std::io::Result<()> {
        info!("connecting to udp://{}", self.socket.peer_addr()?);
        tokio::select! {
            _ = self.socket.connect(self.socket.peer_addr()?) => Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(5)) => Err(std::io::Error::other("connection timeout"))
        }
    }
}
