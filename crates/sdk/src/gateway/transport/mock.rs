use crate::runtime::error::RuntimeError;
use crate::gateway::transport::{ClientTransport, Transport, TransportReceiver, TransportSender};
use async_trait::async_trait;
use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

struct MockTransportInner {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    peer_addr: SocketAddr,
}

pub struct MockTransport {
    inner: Arc<tokio::sync::Mutex<MockTransportInner>>,
    local_addr: SocketAddr,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::with_capacity(100)
    }

    pub fn with_capacity(buffer_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer_size);
        let local_addr = "127.0.0.1:0".parse().unwrap();
        let peer_addr = "127.0.0.1:0".parse().unwrap();

        MockTransport {
            inner: Arc::new(tokio::sync::Mutex::new(MockTransportInner {
                tx,
                rx,
                peer_addr,
            })),
            local_addr,
        }
    }

    pub fn create_pair() -> (Self, Self) {
        let (tx1, rx1) = mpsc::channel(100);
        let (tx2, rx2) = mpsc::channel(100);

        let addr1 = "127.0.0.1:10001".parse().unwrap();
        let addr2 = "127.0.0.1:10002".parse().unwrap();

        let transport1 = MockTransport {
            inner: Arc::new(tokio::sync::Mutex::new(MockTransportInner {
                tx: tx1,
                rx: rx2,
                peer_addr: addr2,
            })),
            local_addr: addr1,
        };

        let transport2 = MockTransport {
            inner: Arc::new(tokio::sync::Mutex::new(MockTransportInner {
                tx: tx2,
                rx: rx1,
                peer_addr: addr1,
            })),
            local_addr: addr2,
        };

        (transport1, transport2)
    }

    pub fn set_peer(&self, peer: &MockTransport) {
        let peer_inner = Arc::clone(&peer.inner);
        let mut inner_guard = futures::executor::block_on(self.inner.lock());

        let peer_guard = futures::executor::block_on(peer_inner.lock());
        inner_guard.peer_addr = peer.local_addr;

        // Note: В реальности нужно аккуратно обменяться каналами
        // Для простоты используем создание новой пары
    }

    pub fn create_sender(&self) -> MockTransportSender {
        let inner = Arc::clone(&self.inner);
        MockTransportSender { inner }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        futures::executor::block_on(async {
            let inner = self.inner.lock().await;
            inner.peer_addr
        })
    }
}

pub struct MockTransportSender {
    inner: Arc<tokio::sync::Mutex<MockTransportInner>>,
}

impl MockTransportSender {
    pub async fn send(&self, data: Vec<u8>) -> Result<(), RuntimeError> {
        let inner = self.inner.lock().await;
        inner.tx.send(data).await.map_err(|e| {
            RuntimeError::IO(format!("Failed to send data: {}", e))
        })?;
        Ok(())
    }
}

#[async_trait]
impl TransportSender for MockTransport {
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> std::io::Result<usize> {
        let inner = self.inner.lock().await;
        inner.tx.send(data.to_vec()).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("Send error: {}", e))
        })?;
        Ok(data.len())
    }

    async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        let inner = self.inner.lock().await;
        inner.tx.send(data.to_vec()).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("Send error: {}", e))
        })?;
        Ok(data.len())
    }
}

#[async_trait]
impl TransportReceiver for MockTransport {
    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut inner = self.inner.lock().await;

        match inner.rx.recv().await {
            Some(data) => {
                let len = data.len().min(buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                Ok((len, inner.peer_addr))
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Channel closed"
            )),
        }
    }

    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock().await;

        match inner.rx.recv().await {
            Some(data) => {
                let len = data.len().min(buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Channel closed"
            )),
        }
    }
}

impl Transport for MockTransport {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl ClientTransport for MockTransport {
    async fn connect(&self) -> std::io::Result<()> {
        info!("MockTransport::connect called - ready for communication");
        Ok(())
    }
}

impl Clone for MockTransport {
    fn clone(&self) -> Self {
        MockTransport {
            inner: Arc::clone(&self.inner),
            local_addr: self.local_addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_transport_pair() {
        let (mut transport1, mut transport2) = MockTransport::create_pair();

        // Тест отправки от transport1 к transport2
        let test_data = b"Hello from transport1";
        transport1.send_to(test_data, &transport2.local_addr()).await.unwrap();

        let mut buffer = [0u8; 1024];
        let (size, addr) = transport2.recv_from(&mut buffer).await.unwrap();

        assert_eq!(&buffer[..size], test_data);
        assert_eq!(addr, transport1.local_addr());

        // Тест отправки от transport2 к transport1
        let test_data2 = b"Hello from transport2";
        transport2.send_to(test_data2, &transport1.local_addr()).await.unwrap();

        let (size2, addr2) = transport1.recv_from(&mut buffer).await.unwrap();

        assert_eq!(&buffer[..size2], test_data2);
        assert_eq!(addr2, transport2.local_addr());
    }

    #[tokio::test]
    async fn test_mock_transport_sender() {
        let transport = MockTransport::new();
        let sender = transport.create_sender();

        let test_data = b"Test message";
        sender.send(test_data.to_vec()).await.unwrap();

        let mut buffer = [0u8; 1024];
        let size = transport.recv(&mut buffer).await.unwrap();

        assert_eq!(&buffer[..size], test_data);
    }
}