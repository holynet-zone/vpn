mod handshake;
mod data;
mod tun;
mod transport;

#[cfg(feature = "udp")]
pub use crate::runtime::transport::udp::UdpTransport;

#[cfg(feature = "ws")]
pub use crate::runtime::transport::ws::WsTransport;

use crate::{
    runtime::{
        error::RuntimeError,
        worker::{
            data::{data_tun_executor, data_udp_executor, keepalive_sender},
            transport::{transport_listener, transport_sender},
            tun::{tun_listener, tun_sender},
        }
    },
};
use shared::connection_config::{CredentialsConfig, RuntimeConfig};
use shared::protocol::{EncryptedData, Packet};
use shared::session::Alg;
use std::time::Duration;
use std::{
    net::SocketAddr,
    sync::Arc
};
use tokio::sync::{mpsc, watch};
use tracing::{info};
use tun_rs::AsyncDevice;
use crate::runtime::state::RuntimeState;
use crate::runtime::transport::Transport;

pub(crate) async fn create(
    addr: SocketAddr,
    tun: Arc<AsyncDevice>,
    state_tx: watch::Sender<RuntimeState>,
    cred: CredentialsConfig,
    alg: Alg,
    runtime_config: RuntimeConfig,
) -> Result<(), RuntimeError> {

    let transport: Arc<dyn Transport> = match () {
        #[cfg(feature = "udp")]
        _ if cfg!(feature = "udp") => {
            Arc::new(UdpTransport::new(
                addr,
                runtime_config.so_rcvbuf,
                runtime_config.so_sndbuf,
            )?)
        }
        #[cfg(feature = "ws")]
        _ if cfg!(feature = "ws") => {
            Arc::new(WsTransport::new(addr))
        }
        _ => unreachable!("transport is not enabled, please enable transport features")
    };
    
    let (udp_sender_tx, udp_sender_rx) = mpsc::channel::<Packet>(runtime_config.out_udp_buf);
    let (tun_sender_tx, tun_sender_rx) = mpsc::channel::<Vec<u8>>(runtime_config.out_tun_buf);
    let (data_udp_tx, data_udp_rx) = mpsc::channel::<EncryptedData>(runtime_config.data_udp_buf);
    let (data_tun_tx, data_tun_rx) = mpsc::channel::<Vec<u8>>(runtime_config.data_tun_buf);

    // Handle incoming UDP packets
    tokio::spawn(transport_listener(state_tx.clone(), transport.clone(), data_udp_tx));

    // Handle outgoing UDP packets
    tokio::spawn(transport_sender(state_tx.clone(), transport.clone(), udp_sender_rx));


    // Executors
    tokio::spawn(data_tun_executor(
        state_tx.clone(),
        data_tun_rx,
        udp_sender_tx.clone(),
    ));
    
    tokio::spawn(data_udp_executor(
        state_tx.clone(),
        data_udp_rx,
        tun_sender_tx
    ));
    
    
    // Handle incoming TUN packets
    tokio::spawn(tun_listener(
        state_tx.clone(),
        tun.clone(),
        data_tun_tx
    ));

    // Handle outgoing TUN packets
    tokio::spawn(tun_sender(
        state_tx.clone(),
        tun.clone(),
        tun_sender_rx
    ));


    match runtime_config.keepalive {
        Some(duration) => {
            info!("starting keepalive with interval {:?}", duration);
            tokio::spawn(keepalive_sender(
                state_tx.clone(),
                udp_sender_tx,
                Duration::from_secs(duration),
            ));
        },
        None => info!("keepalive is disabled")
    }
    
    // handshake_executor
    handshake::handshake_executor(
        transport.clone(),
        state_tx.clone(),
        cred,
        alg,
        Duration::from_secs(runtime_config.handshake_timeout)
    ).await;
    
    Ok(())
}
