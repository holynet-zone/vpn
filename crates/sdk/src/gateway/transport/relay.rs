//! Client transport that tunnels through a transparent inter-node relay.
//!
//! Wraps an inner [`ClientTransport`] connected to the relay node (US) and
//! carries an end-to-end session with the destination node (RU): `connect` opens
//! a relay (`RelayOpen` -> `RelayOpened{relay_id}`), then every `send`/`recv`
//! wraps/unwraps the opaque payload in a `RelayData{relay_id,..}` frame. The
//! relay never sees the inner (Noise-encrypted) bytes, so the existing client
//! stack runs unchanged over this transport for a true end-to-end tunnel.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::crypto::PublicKey;
use crate::gateway::transport::{ClientTransport, Transport, TransportReceiver, TransportSender};
use crate::protocol::PacketRef;
use crate::runtime::crypto::{
    RELAY_DATA_HDR_LEN, TYPE_RELAY_DATA, relay_open_frame, write_relay_data,
};

pub struct RelayTransport<T: ClientTransport> {
    inner: Arc<T>,
    dest_pk: PublicKey,
    open_timeout: Duration,
    relay_id: AtomicU32,
}

impl<T: ClientTransport> RelayTransport<T> {
    pub fn new(inner: Arc<T>, dest_pk: PublicKey, open_timeout: Duration) -> Self {
        Self {
            inner,
            dest_pk,
            open_timeout,
            relay_id: AtomicU32::new(0),
        }
    }
}

impl<T: ClientTransport> TransportSender for RelayTransport<T> {
    fn send<'a>(&'a self, data: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            let id = self.relay_id.load(Ordering::Relaxed);
            let mut frame = vec![0u8; RELAY_DATA_HDR_LEN + data.len()];
            let n = write_relay_data(&mut frame, id, data);
            self.inner.send(&frame[..n]).await?;
            Ok(data.len())
        }
    }

    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        _addr: &'a SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        // The relay leg is a connected socket to the relay node; the destination
        // is fixed by the relay_id, so `addr` is irrelevant here.
        self.send(data)
    }
}

impl<T: ClientTransport> TransportReceiver for RelayTransport<T> {
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            let id = self.relay_id.load(Ordering::Relaxed);
            loop {
                let n = self.inner.recv(buffer).await?;
                // Strip the RelayData header in place; ignore stray frames.
                if n >= RELAY_DATA_HDR_LEN
                    && buffer[0] == TYPE_RELAY_DATA
                    && u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) == id
                {
                    buffer.copy_within(RELAY_DATA_HDR_LEN..n, 0);
                    return Ok(n - RELAY_DATA_HDR_LEN);
                }
            }
        }
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a {
        async move {
            let n = self.recv(buffer).await?;
            Ok((n, SocketAddr::from(([0, 0, 0, 0], 0))))
        }
    }
}

impl<T: ClientTransport> Transport for RelayTransport<T> {}

impl<T: ClientTransport> ClientTransport for RelayTransport<T> {
    fn connect<'a>(&'a self) -> impl Future<Output = io::Result<()>> + Send + 'a {
        async move {
            self.inner.connect().await?;
            self.inner
                .send(&relay_open_frame(self.dest_pk.as_bytes()))
                .await?;

            let mut buf = [0u8; 64];
            let fut = async {
                loop {
                    let n = self.inner.recv(&mut buf).await?;
                    if let Some(PacketRef::RelayOpened(id)) = PacketRef::from_bytes(&buf[..n]) {
                        return Ok::<u32, io::Error>(id);
                    }
                }
            };
            let id = tokio::time::timeout(self.open_timeout, fut)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay open timeout"))??;
            if id == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "relay refused (unknown destination or capacity)",
                ));
            }
            self.relay_id.store(id, Ordering::Relaxed);
            Ok(())
        }
    }
}
