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

    /// Batched receive via `recvmmsg`: one syscall drains up to `MAX_MMSG`
    /// already-queued datagrams into `bufs`. Waits (async) for the first one.
    #[cfg(target_os = "linux")]
    async fn recv_mmsg(
        &self,
        bufs: &mut [Vec<u8>],
        lens: &mut [usize],
        addrs: &mut [SocketAddr],
    ) -> std::io::Result<usize> {
        use tokio::io::Interest;
        loop {
            self.socket.readable().await?;
            match self.socket.try_io(Interest::READABLE, || {
                recvmmsg_batch(&self.socket, bufs, lens, addrs)
            }) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Largest datagram batch a single `recvmmsg` call gathers.
#[cfg(target_os = "linux")]
const MAX_MMSG: usize = 64;

/// One non-blocking `recvmmsg`. Fills `bufs[i]`/`lens[i]`/`addrs[i]` for each of
/// the returned datagrams. `bufs`, `lens`, `addrs` must be the same length.
#[cfg(target_os = "linux")]
fn recvmmsg_batch(
    socket: &UdpSocket,
    bufs: &mut [Vec<u8>],
    lens: &mut [usize],
    addrs: &mut [SocketAddr],
) -> std::io::Result<usize> {
    use nix::libc;
    use std::os::fd::AsRawFd;

    let vlen = bufs.len().min(lens.len()).min(addrs.len()).min(MAX_MMSG);

    // Per-message scratch. Each `mmsghdr` points at its own single-entry iovec
    // and its own sockaddr storage; all live on this stack frame for the call.
    let mut iovecs: [libc::iovec; MAX_MMSG] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; MAX_MMSG] = unsafe { std::mem::zeroed() };
    let mut names: [libc::sockaddr_storage; MAX_MMSG] = unsafe { std::mem::zeroed() };

    for i in 0..vlen {
        iovecs[i].iov_base = bufs[i].as_mut_ptr() as *mut libc::c_void;
        iovecs[i].iov_len = bufs[i].len();
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &mut names[i] as *mut _ as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    }

    // SAFETY: `msgs[..vlen]` are fully initialised above and outlive the call;
    // the socket fd is valid for the borrow of `socket`.
    let n = unsafe {
        libc::recvmmsg(
            socket.as_raw_fd(),
            msgs.as_mut_ptr(),
            vlen as libc::c_uint,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let count = n as usize;
    for i in 0..count {
        lens[i] = msgs[i].msg_len as usize;
        if let Some(addr) = storage_to_socketaddr(&names[i]) {
            addrs[i] = addr;
        }
    }
    Ok(count)
}

/// Convert a kernel-filled `sockaddr_storage` to a [`SocketAddr`] (v4/v6).
#[cfg(target_os = "linux")]
fn storage_to_socketaddr(ss: &nix::libc::sockaddr_storage) -> Option<SocketAddr> {
    use nix::libc;
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: ss_family == AF_INET => the storage holds a sockaddr_in.
            let sin = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            // SAFETY: ss_family == AF_INET6 => the storage holds a sockaddr_in6.
            let sin6 = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::new(IpAddr::V6(ip), u16::from_be(sin6.sin6_port)))
        }
        _ => None,
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
