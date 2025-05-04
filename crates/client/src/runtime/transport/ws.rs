use crate::runtime::error::RuntimeError;
use crate::runtime::transport::{Transport, TransportReceiver, TransportSender};
use async_trait::async_trait;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};


pub struct WsTransport {
    write: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    read: Arc<Mutex<SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>>>,
}

impl WsTransport {
    pub async fn connect(addr: SocketAddr) -> Result<Self, RuntimeError> {
        tracing::info!("connecting to ws://{}", addr);
        let request = format!("ws://{addr}").into_client_request().unwrap();
        let (ws_stream, _) = connect_async(request)
            .await
            .map_err(|e| RuntimeError::IO(format!(
                "Failed to connect to WebSocket server: {}", e
            )))?;
        
        let (write, read) = ws_stream.split();

        Ok(Self { write: Arc::new(Mutex::new(write)) , read: Arc::new(Mutex::new(read)) })
    }
}

#[async_trait]
impl TransportReceiver for WsTransport {

    #[inline(always)]
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut read = self.read.lock().await;
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Binary(data) = msg {
                let len = data.len().min(buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                return Ok(len);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "WebSocket connection closed"
        ))
    }
}

#[async_trait]
impl TransportSender for WsTransport {
    #[inline(always)]
    async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        self.write.lock().await
            .send(Message::Binary(data.to_vec().into()))
            .await
            .map(|_| data.len())
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string()
            ))
    }
}

impl Transport for WsTransport{}
