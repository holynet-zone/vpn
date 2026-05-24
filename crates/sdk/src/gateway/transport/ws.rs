use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use dashmap::DashMap;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, accept_async, connect_async};
use tracing::{debug, info};

use crate::gateway::transport::{ClientTransport, Transport, TransportReceiver, TransportSender};
use crate::runtime::buf_pool::BufPool;
use crate::runtime::error::RuntimeError;

// ---------------------------------------------------------------------------
// Server-side transport
// ---------------------------------------------------------------------------

pub struct WsTransport {
    listener: TcpListener,
    active_connections: Arc<DashMap<SocketAddr, SplitSink<WebSocketStream<TcpStream>, Message>>>,
    // Mutex without Arc: WsTransport is already wrapped in Arc by the caller.
    // recv_from needs &self so we use Mutex for interior mutability.
    // tokio::sync::Mutex is required because recv() is async (lock held across await).
    message_queue: Mutex<mpsc::UnboundedReceiver<(Bytes, SocketAddr)>>,
    message_sender: mpsc::UnboundedSender<(Bytes, SocketAddr)>,
    // Pooled allocation for outbound WS messages — reuses Arc<[u8]> slots instead of
    // calling malloc on every send. Held only for the memcpy, never across .await.
    send_pool: StdMutex<BufPool>,
}

impl WsTransport {
    #[cfg(feature = "ws-reuse-port")]
    pub fn new_pool(
        addr: SocketAddr,
        so_rcvbuf: usize,
        so_sndbuf: usize,
        count: usize,
    ) -> Result<Vec<Self>, RuntimeError> {
        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;

        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;
        socket.set_recv_buffer_size(so_rcvbuf)?;
        socket.set_send_buffer_size(so_sndbuf)?;
        socket.set_tos_v4(0b101110 << 2)?;
        socket.bind(&addr.into())?;
        socket.listen(10000)?;

        info!("Runtime running on ws://{} with {} workers", addr, count);

        let active_connections = Arc::new(DashMap::new());

        let mut listeners = Vec::with_capacity(count);
        for _ in 0..count - 1 {
            let cloned = socket.try_clone()?;
            let listener = TcpListener::from_std(cloned.into())?;
            let (sender, receiver) = mpsc::unbounded_channel();
            listeners.push(Self {
                listener,
                active_connections: active_connections.clone(),
                message_queue: Mutex::new(receiver),
                message_sender: sender,
                send_pool: StdMutex::new(BufPool::new(65536)),
            });
        }

        let (sender, receiver) = mpsc::unbounded_channel();
        let listener = TcpListener::from_std(socket.into())?;
        listeners.push(Self {
            listener,
            active_connections,
            message_queue: Mutex::new(receiver),
            message_sender: sender,
            send_pool: StdMutex::new(BufPool::new(65536)),
        });

        debug!("make ws transport pool with {} workers", listeners.len());
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
                        tracing::error!("WebSocket handshake error: {}", e);
                        return;
                    }
                };
                let (write, read) = ws_stream.split();
                connections.insert(addr, write);
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

impl TransportReceiver for WsTransport {
    #[inline(always)]
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.message_queue.lock().await.recv().await {
            Some((data, addr)) => {
                let len = data.len().min(buffer.len());
                buffer[..len].copy_from_slice(&data[..len]);
                Ok((len, addr))
            }
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")),
        }
    }

    #[inline(always)]
    async fn recv(&self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "server transport: use recv_from",
        ))
    }
}

impl TransportSender for WsTransport {
    #[inline(always)]
    async fn send_to(&self, data: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        if let Some(mut writer) = self.active_connections.get_mut(addr) {
            // Copy into a pooled buffer (no malloc after warmup); release the
            // lock before the async send so we never hold it across an await.
            let bytes = self.send_pool.lock().unwrap().copy_to_bytes(data);
            writer
                .value_mut()
                .send(Message::Binary(bytes))
                .await
                .map_err(io::Error::other)?;
            Ok(data.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "address not found",
            ))
        }
    }

    #[inline(always)]
    async fn send(&self, _data: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "server transport: use send_to",
        ))
    }
}

impl Transport for WsTransport {}

// ---------------------------------------------------------------------------
// Client-side transport (WsClientTransport)
// ---------------------------------------------------------------------------

type ClientSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type ClientStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

pub struct WsClientTransport {
    addr: SocketAddr,
    write: Arc<Mutex<Option<ClientSink>>>,
    read: Arc<Mutex<Option<ClientStream>>>,
    send_pool: StdMutex<BufPool>,
}

impl WsClientTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            write: Arc::new(Mutex::new(None)),
            read: Arc::new(Mutex::new(None)),
            send_pool: StdMutex::new(BufPool::new(65536)),
        }
    }
}

impl TransportReceiver for WsClientTransport {
    #[inline(always)]
    async fn recv_from(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "client transport: use recv",
        ))
    }

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
                    "WebSocket connection closed",
                ))
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WebSocket connection not established",
            )),
        }
    }
}

impl TransportSender for WsClientTransport {
    #[inline(always)]
    async fn send_to(&self, _data: &[u8], _addr: &SocketAddr) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "client transport: use send",
        ))
    }

    #[inline(always)]
    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        // Copy into a pooled buffer before acquiring the async write lock so
        // the std Mutex is never held across an await point.
        let bytes = self.send_pool.lock().unwrap().copy_to_bytes(data);
        match self.write.lock().await.as_mut() {
            Some(write) => write
                .send(Message::Binary(bytes))
                .await
                .map(|_| data.len())
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WebSocket connection not established",
            )),
        }
    }
}

impl Transport for WsClientTransport {}

impl ClientTransport for WsClientTransport {
    async fn connect(&self) -> io::Result<()> {
        info!("connecting to ws://{}", self.addr);
        let request = format!("ws://{}", self.addr)
            .into_client_request()
            .map_err(|e| io::Error::other(e.to_string()))?;

        let (ws_stream, _) = connect_async(request).await.map_err(io::Error::other)?;

        let (write, read) = ws_stream.split();
        *self.write.lock().await = Some(write);
        *self.read.lock().await = Some(read);

        Ok(())
    }
}
