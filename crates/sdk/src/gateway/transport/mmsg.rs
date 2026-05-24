//! Batch UDP receive via `recvmmsg(2)`.
//!
//! ## Буферная раскладка
//!
//! `bufs`: 32 × `[u8; 2048]` — 64 КБ contiguous, помещается в L2.
//! Для single-stream hot path используется только slot 0 (n=1).
//! При multi-stream / high-PPS воркерах все 32 слота заполнены.

use std::future::Future;
use std::net::SocketAddr;

use super::Transport;

/// Число датаграмм за один вызов `recvmmsg`.
pub const BATCH_SIZE: usize = 32;

/// Размер слота: с запасом относительно TUN MTU 1420 Б + Noise/заголовок ~50 Б.
/// 32 × 2048 = 64 КБ — помещается в L2 кеш целиком.
pub const RECV_BUF_SIZE: usize = 2048;

/// Pre-allocated batch-буфер для одного воркера.
///
/// Создаётся один раз при старте задачи; на каждой итерации цикла передаётся
/// в [`RecvMmsg::recv_mmsg`] по `&mut`.  Ноль аллокаций в steady state.
pub struct RecvBatch {
    /// Contiguous block: 32 × 2048 = 64 КБ.
    pub(crate) bufs: Vec<[u8; RECV_BUF_SIZE]>,
    /// Адрес источника для каждого полученного пакета.
    pub(crate) addrs: Vec<SocketAddr>,
    /// Длины полезной нагрузки (заполняется `recv_mmsg`).
    pub(crate) lens: Vec<usize>,
    /// Число валидных слотов после последнего вызова `recv_mmsg`.
    n: usize,
    /// Сырые `sockaddr_storage` — нужны только Linux UDP-пути.
    #[cfg(target_os = "linux")]
    pub(crate) raw_addrs: Vec<libc::sockaddr_storage>,
}

impl RecvBatch {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        let raw_addrs = (0..BATCH_SIZE)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();

        Self {
            bufs: vec![[0u8; RECV_BUF_SIZE]; BATCH_SIZE],
            addrs: vec!["0.0.0.0:0".parse().unwrap(); BATCH_SIZE],
            lens: vec![0usize; BATCH_SIZE],
            n: 0,
            #[cfg(target_os = "linux")]
            raw_addrs,
        }
    }

    /// Число пакетов после последнего `recv_mmsg`.
    #[inline]
    pub fn len(&self) -> usize {
        self.n
    }

    /// Payload-срез и адрес источника для слота `idx`.
    #[inline]
    pub fn packet(&self, idx: usize) -> (&[u8], SocketAddr) {
        (&self.bufs[idx][..self.lens[idx]], self.addrs[idx])
    }

    #[inline]
    pub(crate) fn set_len(&mut self, n: usize) {
        self.n = n;
    }
}

impl Default for RecvBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Extension-трейт: батчевый приём датаграмм.
///
/// `UdpTransport` реализует через `recvmmsg(2)` на Linux.
/// Все остальные транспорты — fallback на одиночный `recv_from`.
pub trait RecvMmsg: Transport {
    fn recv_mmsg<'a>(
        &'a self,
        batch: &'a mut RecvBatch,
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a;
}

// ---------------------------------------------------------------------------
// sockaddr_storage → SocketAddr (только Linux)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) fn sockaddr_to_socket_addr(
    storage: &libc::sockaddr_storage,
    namelen: libc::socklen_t,
) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    unsafe {
        match storage.ss_family as libc::c_int {
            libc::AF_INET
                if namelen
                    >= std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t =>
            {
                let a = &*(storage as *const _ as *const libc::sockaddr_in);
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))),
                    u16::from_be(a.sin_port),
                )
            }
            libc::AF_INET6
                if namelen
                    >= std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t =>
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
