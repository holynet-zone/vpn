mod handshake;
mod data;
mod tun;
mod transport;

use super::session::HolyIp;
use super::{
    error::RuntimeError,
    session::Sessions
};
use crate::config::RuntimeConfig;
use crate::runtime::worker::{
    data::{data_tun_executor, data_transport_executor},
    handshake::handshake_executor,
    tun::{tun_listener, tun_sender},
    transport::{transport_listener, transport_sender}
};
use dashmap::DashMap;
use shared::keys::handshake::{PublicKey, SecretKey};
use shared::protocol::{EncryptedData, EncryptedHandshake, Packet};
use shared::session::SessionId;
use std::{
    net::SocketAddr,
    sync::Arc
};
use tokio::sync::{broadcast, mpsc};
use tracing::info;
use tun_rs::AsyncDevice;
use crate::runtime::transport::Transport;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create(
    transport: Arc<dyn Transport>,
    stop_tx: broadcast::Sender<RuntimeError>,
    sessions: Sessions,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sk: SecretKey,
    tun: AsyncDevice,
    worker_id: usize,
    config: RuntimeConfig
) -> Result<(), RuntimeError> {

    let tun = Arc::new(tun);
    
    let (out_transport_tx, out_transport_rx) = mpsc::channel::<(Packet, SocketAddr)>(config.out_udp_buf);
    let (out_tun_tx, out_tun_rx) = mpsc::channel::<Vec<u8>>(config.out_tun_buf);
    let (handshake_tx, handshake_rx) = mpsc::channel::<(EncryptedHandshake, SocketAddr)>(config.handshake_buf);
    let (data_transport_tx, data_transport_rx) = mpsc::channel::<(SessionId, EncryptedData, SocketAddr)>(config.data_udp_buf);
    let (data_tun_tx, data_tun_rx) = mpsc::channel::<(Vec<u8>, HolyIp)>(config.data_tun_buf);

    #[cfg(feature = "ws")]
    {
        use crate::runtime::transport::ws::WsTransport;
        if let Ok(ws_transport) = transport.clone().downcast::<WsTransport>() {
            tokio::spawn(async move {
                ws_transport.start().await
            });
        }
    }
    // Handle incoming transport packets
    tokio::spawn(transport_listener(stop_tx.subscribe(), transport.clone(), handshake_tx, data_transport_tx));

    // Handle outgoing transport packets
    tokio::spawn(transport_sender(stop_tx.subscribe(), transport.clone(), out_transport_rx));
    
    // Handle incoming TUN packets
    tokio::spawn(tun_listener(stop_tx.subscribe(), tun.clone(), data_tun_tx));
    
    // Handle outgoing TUN packets
    tokio::spawn(tun_sender(stop_tx.subscribe(), tun.clone(), out_tun_rx));
    
    // Executors
    tokio::spawn(handshake_executor(
        stop_tx.subscribe(), 
        handshake_rx, 
        out_transport_tx.clone(), 
        known_clients.clone(), 
        sessions.clone(),
        sk
    ));
    tokio::spawn(data_transport_executor(
        stop_tx.subscribe(), 
        data_transport_rx,
        out_transport_tx.clone(),
        out_tun_tx.clone(),
        sessions.clone(),
        config.session.unwrap_or_default().timeout == 0
    ));

    tokio::spawn(data_tun_executor(
        stop_tx.subscribe(),
        data_tun_rx,
        out_transport_tx.clone(),
        sessions.clone(),
    ));
    

    let mut stop_rx = stop_tx.subscribe();
    tokio::select! {
        _ = stop_rx.recv() => info!("worker {} stopping", worker_id)
    }
    
    Ok(())
}
