//! io_uring UDP transport (Linux only, feature = "udp-uring").
//!
//! ## Отличие от tokio UdpSocket
//!
//! Обычный `recv_from`: epoll → задача проснулась → syscall recvfrom → данные в буфере.
//! Здесь: RECV SQE уже в кольце → ядро заполнило буфер → eventfd готов → задача проснулась →
//! данные уже в зарегистрированном буфере → один memcpy в caller's buf.
//!
//! Итог: устранён syscall recvfrom на горячем пути; буферы зарегистрированы (ядро их пинит),
//! что снижает overhead при DMA-заполнении.

use crate::gateway::transport::{ClientTransport, Transport, TransportReceiver, TransportSender};
use crate::runtime::error::RuntimeError;
use io_uring::{opcode, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::mem::{size_of, zeroed};
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tracing::info;

const BUF_SIZE: usize = 2048;
const NUM_BUFS: usize = 64;
const RING_SIZE: u32 = 256;

// ---------------------------------------------------------------------------
// Inner mutable state (behind Mutex — lock never held across .await)
// ---------------------------------------------------------------------------

struct UringInner {
    ring: IoUring,
    socket_fd: RawFd,
    // Pre-allocated, heap-stable buffers registered with io_uring.
    bufs: Box<[[u8; BUF_SIZE]; NUM_BUFS]>,
    addrs: Box<[libc::sockaddr_storage; NUM_BUFS]>,
    // Kept alive so that the registered buffer addresses remain valid.
    #[allow(dead_code)]
    iovecs: Box<[libc::iovec; NUM_BUFS]>,
    msghdrs: Box<[libc::msghdr; NUM_BUFS]>,
    free: Vec<u16>,
    completions: VecDeque<(u16, usize, SocketAddr)>,
    inflight: usize,
}

// Safety: UringInner is only accessed through Mutex, which serializes all
// thread access. The raw pointers in iovecs/msghdrs are stable heap addresses
// owned exclusively by UringInner and never escaped elsewhere.
unsafe impl Send for UringInner {}
unsafe impl Sync for UringInner {}

impl UringInner {
    fn new(socket_fd: RawFd, event_fd_raw: RawFd) -> std::io::Result<Self> {
        let ring = IoUring::new(RING_SIZE)?;
        ring.submitter().register_eventfd(event_fd_raw)?;

        let mut bufs = Box::new([[0u8; BUF_SIZE]; NUM_BUFS]);
        let mut addrs: Box<[libc::sockaddr_storage; NUM_BUFS]> =
            Box::new(unsafe { zeroed() });
        let mut iovecs: Box<[libc::iovec; NUM_BUFS]> =
            Box::new(unsafe { zeroed() });
        let mut msghdrs: Box<[libc::msghdr; NUM_BUFS]> =
            Box::new(unsafe { zeroed() });

        for i in 0..NUM_BUFS {
            iovecs[i].iov_base = bufs[i].as_mut_ptr() as *mut libc::c_void;
            iovecs[i].iov_len = BUF_SIZE;

            msghdrs[i].msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
            msghdrs[i].msg_namelen =
                size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msghdrs[i].msg_iov = &mut iovecs[i] as *mut libc::iovec;
            msghdrs[i].msg_iovlen = 1;
        }

        Ok(Self {
            ring,
            socket_fd,
            bufs,
            addrs,
            iovecs,
            msghdrs,
            free: (0..NUM_BUFS as u16).collect(),
            completions: VecDeque::new(),
            inflight: 0,
        })
    }

    /// Drain the completion queue; completed entries go into `self.completions`.
    fn poll_completions(&mut self) {
        let mut cq = self.ring.completion();
        cq.sync();
        for cqe in &mut cq {
            let idx = cqe.user_data() as u16;
            self.inflight -= 1;
            let n = cqe.result();
            if n < 0 {
                self.free.push(idx);
            } else {
                let addr = sockaddr_to_socket_addr(
                    &self.addrs[idx as usize],
                    self.msghdrs[idx as usize].msg_namelen,
                );
                self.completions.push_back((idx, n as usize, addr));
            }
        }
    }

    /// Submit RECV SQEs for all free buffer slots, then call ring.submit().
    fn submit_pending(&mut self) -> std::io::Result<()> {
        if self.free.is_empty() {
            return Ok(());
        }
        {
            let mut sq = self.ring.submission();
            while let Some(idx) = self.free.pop() {
                // Reset msg_namelen — kernel sets it to actual addr len on completion.
                self.msghdrs[idx as usize].msg_namelen =
                    size_of::<libc::sockaddr_storage>() as libc::socklen_t;

                let sqe = opcode::RecvMsg::new(
                    types::Fd(self.socket_fd),
                    &mut self.msghdrs[idx as usize] as *mut libc::msghdr,
                )
                .build()
                .user_data(idx as u64);

                // Safety: bufs/addrs/iovecs/msghdrs are heap-pinned for the
                // lifetime of UringInner (Box), so the pointers remain valid.
                unsafe {
                    sq.push(&sqe).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "io_uring SQ full",
                        )
                    })?;
                }
                self.inflight += 1;
            }
        }
        self.ring.submit()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public transport type
// ---------------------------------------------------------------------------

pub struct UringUdpTransport {
    /// Used only for send_to / send — tokio async path is fine for the send side.
    socket: UdpSocket,
    inner: Mutex<UringInner>,
    /// eventfd registered with io_uring; becomes readable when CQEs are available.
    event_fd: AsyncFd<OwnedFd>,
    event_fd_raw: RawFd,
}

impl UringUdpTransport {
    /// Create a pool of transports sharing the same port (SO_REUSEPORT).
    #[cfg(feature = "udp-reuse-port")]
    pub fn new_pool(
        addr: SocketAddr,
        so_rcvbuf: usize,
        so_sndbuf: usize,
        count: usize,
    ) -> Result<Vec<Self>, RuntimeError> {
        let template =
            Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        template.set_nonblocking(true)?;
        template.set_reuse_port(true)?;
        template.set_reuse_address(true)?;
        template.set_recv_buffer_size(so_rcvbuf)?;
        template.set_send_buffer_size(so_sndbuf)?;
        template.set_tos_v4(0b101110 << 2)?;
        template.bind(&addr.into())?;

        info!(
            "Runtime running on udp://{} (io_uring) with {} workers",
            addr, count
        );

        let mut transports = Vec::with_capacity(count);
        for i in 0..count {
            let raw: std::net::UdpSocket = template
                .try_clone()
                .map_err(|e| RuntimeError::IO(format!("clone socket #{}: {}", i, e)))?
                .into();
            transports.push(Self::from_raw(raw)?);
        }
        Ok(transports)
    }

    fn from_raw(raw: std::net::UdpSocket) -> Result<Self, RuntimeError> {
        use std::os::fd::AsRawFd as _;

        let socket_fd = raw.as_raw_fd();

        let event_fd = unsafe {
            let fd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
            if fd < 0 {
                return Err(RuntimeError::IO(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            OwnedFd::from_raw_fd(fd)
        };
        let event_fd_raw = event_fd.as_raw_fd();
        let async_efd = AsyncFd::new(event_fd)
            .map_err(|e| RuntimeError::IO(e.to_string()))?;

        let inner = UringInner::new(socket_fd, event_fd_raw)
            .map_err(|e| RuntimeError::IO(e.to_string()))?;
        let socket = UdpSocket::from_std(raw)?;

        Ok(Self {
            socket,
            inner: Mutex::new(inner),
            event_fd: async_efd,
            event_fd_raw,
        })
    }
}

impl TransportReceiver for UringUdpTransport {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            {
                let mut inner = self.inner.lock().unwrap();
                inner.poll_completions();
                if let Some((idx, n, addr)) = inner.completions.pop_front() {
                    let copy_len = n.min(buf.len());
                    buf[..copy_len]
                        .copy_from_slice(&inner.bufs[idx as usize][..copy_len]);
                    inner.free.push(idx);
                    // Submit only when the completion queue is drained so that
                    // ring.submit() is amortised over a burst, not per-packet.
                    if inner.completions.is_empty() {
                        inner.submit_pending()?;
                    }
                    return Ok((copy_len, addr));
                }
                // Queue empty — submit any freed buffers before sleeping.
                inner.submit_pending()?;
            } // Mutex released before .await

            // Wait for io_uring eventfd to signal new completions.
            let mut guard = self.event_fd.readable().await?;
            let mut val = [0u8; 8];
            unsafe {
                libc::read(self.event_fd_raw, val.as_mut_ptr() as *mut libc::c_void, 8);
            }
            guard.clear_ready();
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (n, _) = self.recv_from(buf).await?;
        Ok(n)
    }
}

impl TransportSender for UringUdpTransport {
    #[inline(always)]
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(data, addr).await
    }

    #[inline(always)]
    async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        self.socket.send(data).await
    }
}

impl Transport for UringUdpTransport {}

impl ClientTransport for UringUdpTransport {
    async fn connect(&self) -> std::io::Result<()> {
        info!("connecting to udp://{}", self.socket.peer_addr()?);
        tokio::select! {
            _ = self.socket.connect(self.socket.peer_addr()?) => Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(5)) =>
                Err(std::io::Error::other("connection timeout")),
        }
    }
}

// ---------------------------------------------------------------------------
// sockaddr_storage → SocketAddr
// ---------------------------------------------------------------------------

pub(crate) fn sockaddr_to_socket_addr(
    storage: &libc::sockaddr_storage,
    namelen: libc::socklen_t,
) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    unsafe {
        match storage.ss_family as libc::c_int {
            libc::AF_INET
                if namelen
                    >= size_of::<libc::sockaddr_in>() as libc::socklen_t =>
            {
                let a = &*(storage as *const _ as *const libc::sockaddr_in);
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))),
                    u16::from_be(a.sin_port),
                )
            }
            libc::AF_INET6
                if namelen
                    >= size_of::<libc::sockaddr_in6>() as libc::socklen_t =>
            {
                let a = &*(storage as *const _ as *const libc::sockaddr_in6);
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)),
                    u16::from_be(a.sin6_port),
                )
            }
            _ => "0.0.0.0:0".parse().unwrap(),
        }
    }
}
