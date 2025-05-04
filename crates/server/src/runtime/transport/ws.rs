use std::any::Any;
use crate::runtime::error::RuntimeError;
use crate::runtime::transport::{Transport, TransportReceiver, TransportSender};
use async_trait::async_trait;
use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::{accept_async, WebSocketStream};
use tracing::info;

pub struct WsTransport {
    listener: TcpListener,
    active_connections: Arc<DashMap<SocketAddr, SplitSink<WebSocketStream<TcpStream>, Message>>>,
    message_queue: Arc<Mutex<mpsc::UnboundedReceiver<(Bytes, SocketAddr)>>>,
    message_sender: mpsc::UnboundedSender<(Bytes, SocketAddr)>
}

impl WsTransport {
    pub fn new_pool(
        addr: SocketAddr,
        so_rcvbuf: usize,
        so_sndbuf: usize,
        count: usize,
    ) -> Result<Vec<Self>, RuntimeError> {
        let socket = Socket::new(
            Domain::for_address(addr),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;

        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;
        socket.set_recv_buffer_size(so_rcvbuf)?;
        socket.set_send_buffer_size(so_sndbuf)?;
        socket.set_tos(0b101110 << 2)?;
        socket.bind(&addr.into())?;
        socket.listen(1024)?;

        info!(
            "Runtime running on ws://{} with {} workers",
            addr,
            count
        );

        let mut listeners = Vec::with_capacity(count);
        for _ in 0..count - 1 {
            let cloned = socket.try_clone()?;
            let listener = TcpListener::from_std(cloned.into())?;
            let (sender, receiver) = mpsc::unbounded_channel();
            listeners.push(Self {
                listener,
                active_connections: Arc::new(DashMap::new()),
                message_queue: Arc::new(Mutex::new(receiver)),
                message_sender: sender,
            });
        }
        
        let (sender, receiver) = mpsc::unbounded_channel();
        let listener = TcpListener::from_std(socket.into())?;
        listeners.push(Self {
            listener,
            active_connections: Arc::new(DashMap::new()),
            message_queue: Arc::new(Mutex::new(receiver)),
            message_sender: sender,
        });
        Ok(listeners)
    }

    pub async fn start(&self) -> Result<(), RuntimeError> {
        loop {
            let (tcp_stream, addr) = self.listener.accept().await?;
            let message_sender = self.message_sender.clone();
            let connections = self.active_connections.clone();
            tokio::spawn(async move {
                let ws_stream = match accept_async(tcp_stream).await {
                    Ok(ws) => ws,
                    Err(e) => {
                        eprintln!("WebSocket handshake error: {}", e);
                        return;
                    }
                };
                let (write, read) = ws_stream.split();
                connections.insert(addr, write);
                // Обработка входящих сообщений
                tokio::spawn(async move {
                    let mut read = read;
                    while let Some(Ok(msg)) = read.next().await {
                        if let Message::Binary(data) = msg {
                            let _ = message_sender.send((data, addr));
                        }
                    }
                    connections.remove(&addr);
                });
            });
        }
    }
}


#[async_trait]
impl TransportReceiver for WsTransport {
    #[inline(always)]
    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match self.message_queue.lock().await.recv().await { // todo mutex
            Some((data, addr)) => {
                let len = data.len().min(buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                Ok((len, addr))
            }
            None => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Channel closed")),
        }
    }
}

#[async_trait]
impl TransportSender for WsTransport {
    #[inline(always)]
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> std::io::Result<usize> {
        if let Some(mut writer) = self.active_connections.get_mut(addr) {
            writer.value_mut().send(Message::Binary(data.to_vec().into())).await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(data.len())
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "Address not found"))
        }
    }
}

impl Transport for WsTransport {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl dyn Transport {
    pub fn downcast<T: Transport + 'static>(self: Arc<Self>) -> Result<Arc<T>, Arc<dyn Transport>> {
        if self.as_any().is::<T>() {
            let ptr = Arc::into_raw(self);
            Ok(unsafe { Arc::from_raw(ptr as *const T) })
        } else {
            Err(self)
        }
    }
}