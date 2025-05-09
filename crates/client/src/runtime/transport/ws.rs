use std::io;
use crate::runtime::transport::{Transport, TransportReceiver, TransportSender};
use async_trait::async_trait;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::anyhow;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::info;


pub struct WsTransport {
    addr: SocketAddr,
    write: Arc<Mutex<Option<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>>,
    read: Arc<Mutex<Option<SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>>>>,
}

impl WsTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self {addr, write: Arc::new(Mutex::new(None)) , read: Arc::new(Mutex::new(None)) }
    }
}

#[async_trait]
impl TransportReceiver for WsTransport {

    #[inline(always)]
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.read.lock().await.as_mut() {
            Some(read) => {
                while let Some(Ok(msg)) = read.next().await {
                    if let Message::Binary(data) = msg {
                        let len = data.len().min(buffer.len());
                        buffer[..len].copy_from_slice(&data[..len]);
                        return Ok(len);
                    }
                }

                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "WebSocket connection closed"
                ))
            },
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WebSocket connection not established"
            ))
        }
    }
}

#[async_trait]
impl TransportSender for WsTransport {
    
    #[inline(always)]
    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        match self.write.lock().await.as_mut() {
            Some(write) => write
                .send(Message::Binary(data.to_vec().into()))
                .await
                .map(|_| data.len())
                .map_err(|e| io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    e.to_string()
                )),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WebSocket connection not established"
            ))
        }
    }
}

#[async_trait]
impl Transport for WsTransport{
    async fn connect(&self) -> io::Result<()> {
        info!("connecting to ws://{}", self.addr);
        let request = format!("ws://{}", self.addr).into_client_request().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                anyhow!("failed to create WebSocket request: {}", e)
            )
        })?;

        let (ws_stream, _) = connect_async(request)
            .await
            .map_err(|e| io::Error::new(
                io::ErrorKind::Other,
                anyhow!("failed to connect to WebSocket server: {}", e)
            ))?;
        
        let (write, read) = ws_stream.split();

        let mut write_lock = self.write.lock().await;
        *write_lock = Some(write);
        let mut read_lock = self.read.lock().await;
        *read_lock = Some(read);

        Ok(())
    }
}
