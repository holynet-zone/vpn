mod handshake;
mod data;
mod tun;
mod transport;

#[cfg(feature = "udp")]
pub use crate::runtime::transport::udp::UdpTransport;

#[cfg(feature = "ws")]
pub use crate::runtime::transport::ws::WsTransport;

use crate::{
    network::RouteState,
    runtime::{
        error::RuntimeError,
        worker::{
            data::{data_tun_executor, data_udp_executor, keepalive_sender},
            handshake::handshake_step,
            transport::{transport_listener, transport_sender},
            tun::{tun_listener, tun_sender},
        }
    },
};
use shared::connection_config::{CredentialsConfig, InterfaceConfig, RuntimeConfig};
use shared::protocol::{EncryptedData, Packet};
use shared::session::Alg;
use shared::tun::setup_tun;
use std::time::Duration;
use std::{
    net::SocketAddr,
    sync::Arc
};
use tokio::sync::broadcast::{Sender};
use tokio::sync::mpsc;
use tracing::{info};
use crate::runtime::transport::Transport;

pub(crate) async fn create(
    addr: SocketAddr,
    stop_tx: Sender<RuntimeError>,
    cred: CredentialsConfig,
    alg: Alg,
    runtime_config: RuntimeConfig,
    iface_config: InterfaceConfig,
) -> Result<(), RuntimeError> {

    let transport: Arc<dyn Transport> = match () {
        #[cfg(feature = "udp")]
        _ if cfg!(feature = "udp") => {
            info!("using UDP transport");
            Arc::new(UdpTransport::new(
                addr,
                runtime_config.so_rcvbuf,
                runtime_config.so_sndbuf,
            )?)
        }
        #[cfg(feature = "ws")]
        _ if cfg!(feature = "ws") => {
            info!("using WebSocket transport");
            Arc::new(WsTransport::connect(addr).await?)
        }
        _ => unreachable!("transport is not enabled, please enable transport features")
    };
    
    let (udp_sender_tx, udp_sender_rx) = mpsc::channel::<Packet>(runtime_config.out_udp_buf);
    let (tun_sender_tx, tun_sender_rx) = mpsc::channel::<Vec<u8>>(runtime_config.out_tun_buf);
    let (data_udp_tx, data_udp_rx) = mpsc::channel::<EncryptedData>(runtime_config.data_udp_buf);
    let (data_tun_tx, data_tun_rx) = mpsc::channel::<Vec<u8>>(runtime_config.data_tun_buf);
    
    // Handshake step
    let (handshake_payload, state) = match tokio::spawn(handshake_step(
        transport.clone(),
        cred,
        alg,
        Duration::from_millis(runtime_config.handshake_timeout)
    )).await.unwrap() { // todo unwrap
        Ok((p, state)) => (p, Arc::new(state)),
        Err(err) => {
            stop_tx.send(err.clone())?;
            return Err(err);
        }
    };

    // Handle incoming UDP packets
    tokio::spawn(transport_listener(stop_tx.clone(), stop_tx.subscribe(), transport.clone(), data_udp_tx));

    // Handle outgoing UDP packets
    tokio::spawn(transport_sender(stop_tx.clone(), stop_tx.subscribe(), transport.clone(), udp_sender_rx));


    // Executors
    tokio::spawn(data_tun_executor(
        stop_tx.clone(),
        stop_tx.subscribe(),
        data_tun_rx,
        udp_sender_tx.clone(),
        state.clone(),
        handshake_payload.sid,
    ));
    
    tokio::spawn(data_udp_executor(
        stop_tx.clone(),
        stop_tx.subscribe(),
        data_udp_rx,
        tun_sender_tx,
        state.clone()
    ));
    
    let tun = Arc::new(setup_tun(
        iface_config.name.clone(),
        iface_config.mtu,
        handshake_payload.ipaddr,
        32,
        false
    ).await?);
    
    // move from runtime
    let mut routes = RouteState::new(addr.ip(), iface_config.name)
        .build()?;
    
    // Handle incoming TUN packets
    tokio::spawn(tun_listener(
        stop_tx.clone(),
        stop_tx.subscribe(),
        tun.clone(),
        data_tun_tx
    ));

    // Handle outgoing TUN packets
    tokio::spawn(tun_sender(
        stop_tx.clone(),
        stop_tx.subscribe(),
        tun.clone(),
        tun_sender_rx
    ));


    match runtime_config.keepalive {
        Some(duration) => {
            info!("starting keepalive transport with interval {:?}", duration);
            tokio::spawn(keepalive_sender(
                stop_tx.clone(),
                stop_tx.subscribe(),
                udp_sender_tx,
                Duration::from_secs(duration),
                state.clone(),
                handshake_payload.sid,
            ));
        },
        None => info!("keepalive transport is disabled")
    }

    let mut stop_rx = stop_tx.subscribe();
    tokio::select! {
        _ = stop_rx.recv() => {
            routes.restore();
            info!("listener stopped")
        }
    }
    
    Ok(())
}
