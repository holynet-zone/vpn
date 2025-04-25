pub mod handshake;
pub mod data;
pub mod udp;
pub mod tun;

use std::{
    net::SocketAddr,
    sync::Arc
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use snow::StatelessTransportState;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::broadcast::{Receiver, Sender};
use tracing::{error, info, warn};
use tun_rs::AsyncDevice;
use shared::protocol::{EncryptedData, Packet};
use shared::connection_config::{CredentialsConfig, RuntimeConfig};


use shared::session::{Alg, SessionId};
use crate::runtime::worker::data::{data_tun_executor, data_udp_executor, keepalive_sender};
use super::error::RuntimeError;
// 
// 
// pub(crate) async fn create(
//     udp_sender: mpsc::Sender<Packet>,
//     tun_sender: mpsc::Sender<Vec<u8>>,
//     stop_tx: Sender<RuntimeError>,
//     data_udp_rx: mpsc::Receiver<EncryptedData>,
//     data_tun_rx: mpsc::Receiver<Vec<u8>>,
//     state: Arc<StatelessTransportState>,
//     sid: SessionId,
// ) -> Result<(), RuntimeError> {
// 
//     // Executors
//     tokio::spawn(data_tun_executor(
//         stop_tx.clone(),
//         stop_tx.subscribe(),
//         data_tun_rx,
//         udp_sender,
//         state.clone(),
//         sid,
//     ));
//     
//     tokio::spawn(data_udp_executor(
//         stop_tx.clone(),
//         stop_tx.subscribe(),
//         data_udp_rx,
//         tun_sender,
//         state.clone()
//     ));
// 
//     let mut stop_rx = stop_tx.subscribe();
//     tokio::select! {
//         _ = stop_rx.recv() => {
//             info!("worker stopped")
//         }
//     }
//     
//     Ok(())
// }
// 
// 
// 
// 
