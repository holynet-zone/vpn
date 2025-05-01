mod handshake;
mod data;
mod tun;
mod udp;

use super::session::HolyIp;
use super::{
    error::RuntimeError,
    session::Sessions
};
use crate::config::RuntimeConfig;
use crate::runtime::worker::{
    data::{data_tun_executor, data_udp_executor},
    handshake::handshake_executor,
    tun::{tun_listener, tun_sender},
    udp::{udp_listener, udp_sender}
};
use dashmap::DashMap;
use shared::keys::handshake::{PublicKey, SecretKey};
use shared::protocol::{EncryptedData, EncryptedHandshake, Packet};
use shared::session::SessionId;
use socket2::Socket;
use std::{
    net::SocketAddr,
    sync::Arc
};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tracing::info;
use tun_rs::AsyncDevice;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create(
    socket: Socket,
    stop_tx: broadcast::Sender<RuntimeError>,
    sessions: Sessions,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sk: SecretKey,
    tun: AsyncDevice,
    worker_id: usize,
    config: RuntimeConfig
) -> Result<(), RuntimeError> {

    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
    let tun = Arc::new(tun);
    
    let (out_udp_tx, out_udp_rx) = mpsc::channel::<(Packet, SocketAddr)>(config.out_udp_buf);
    let (out_tun_tx, out_tun_rx) = mpsc::channel::<Vec<u8>>(config.out_tun_buf);
    let (handshake_tx, handshake_rx) = mpsc::channel::<(EncryptedHandshake, SocketAddr)>(config.handshake_buf);
    let (data_udp_tx, data_udp_rx) = mpsc::channel::<(SessionId, EncryptedData, SocketAddr)>(config.data_udp_buf);
    let (data_tun_tx, data_tun_rx) = mpsc::channel::<(Vec<u8>, HolyIp)>(config.data_tun_buf);


    // Handle incoming UDP packets
    tokio::spawn(udp_listener(stop_tx.subscribe(), socket.clone(), handshake_tx, data_udp_tx));

    // Handle outgoing UDP packets
    tokio::spawn(udp_sender(stop_tx.subscribe(), socket.clone(), out_udp_rx));
    
    // Handle incoming TUN packets
    tokio::spawn(tun_listener(stop_tx.subscribe(), tun.clone(), data_tun_tx));
    
    // Handle outgoing TUN packets
    tokio::spawn(tun_sender(stop_tx.subscribe(), tun.clone(), out_tun_rx));
    
    // Executors
    tokio::spawn(handshake_executor(
        stop_tx.subscribe(), 
        handshake_rx, 
        out_udp_tx.clone(), 
        known_clients.clone(), 
        sessions.clone(),
        sk
    ));
    tokio::spawn(data_udp_executor(
        stop_tx.subscribe(), 
        data_udp_rx,
        out_udp_tx.clone(),
        out_tun_tx.clone(),
        sessions.clone(),
        config.session.unwrap_or_default().timeout == 0
    ));

    tokio::spawn(data_tun_executor(
        stop_tx.subscribe(),
        data_tun_rx,
        out_udp_tx.clone(),
        sessions.clone(),
    ));
    

    let mut stop_rx = stop_tx.subscribe();
    tokio::select! {
        _ = stop_rx.recv() => info!("worker {} stopping", worker_id)
    }
    
    Ok(())
}



// 
// 
// #[cfg(test)]
// mod tests {
//     use std::net::SocketAddr;
//     use tokio::sync::{
//         mpsc,
//         broadcast
//     };
//     use crate::{storage, server};
//     use crate::keys::handshake::{PublicKey, SecretKey};
//     use crate::server::error::RuntimeError;
//     use crate::{DataBody, Packet};
//     use crate::server::response::Response;
//     use crate::server::r#mod::{data_executor, handshake_executor};
//     use crate::session::Alg;
// 
//     #[tokio::test]
//     async fn test() -> anyhow::Result<()> {
//         let psk = SecretKey::generate_x25519();
// 
//         let client_sk = SecretKey::generate_x25519();
//         let client_pk = PublicKey::derive_from(client_sk.clone());
//         let client_alg = Alg::Aes256;
//         let client_sock = SocketAddr::from(([127, 0, 0, 1], 0));
// 
//         let server_sk = SecretKey::generate_x25519();
//         let server_pk = PublicKey::derive_from(server_sk.clone());
// 
//         let subscriber = tracing_subscriber::fmt()
//             .with_max_level(tracing::Level::TRACE)
//             .with_test_writer()
//             .finish();
//         tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
// 
//         let (stop_tx, _) = broadcast::channel::<RuntimeError>(1);
//         let (out_udp_tx, mut out_udp_rx) = mpsc::channel::<(Packet, SocketAddr)>(1000);
//         let (handshake_tx, handshake_rx) = mpsc::channel::<(storage::packet::Handshake, SocketAddr)>(1000);
//         let (data_tx, data_rx) = mpsc::channel::<(storage::packet::DataPacket, SocketAddr)>(1000);
// 
//         let sessions = server::session::Sessions::new();
//         let known_clients = std::sync::Arc::new(dashmap::DashMap::new());
//         known_clients.insert(client_pk.clone(), psk.clone());
// 
//         // Executors
//         println!("exec");
// 
//         tokio::spawn(handshake_executor(
//             stop_tx.subscribe(),
//             handshake_rx,
//             out_udp_tx.clone(),
//             known_clients.clone(),
//             sessions.clone(),
//             server_sk
//         ));
//         tokio::spawn(data_executor(
//             stop_tx.subscribe(),
//             data_rx,
//             out_udp_tx.clone(),
//             sessions.clone(),
//             Some(
//                 std::sync::Arc::new(|req| {
//                     Box::pin(async move {
//                         match req.body {
//                             storage::packet::DataBody::Payload(bytes) => {
//                                 println!("server handle {} bytes payload, sid: {}", bytes.len(), req.sid);
//                                 Response::Data(DataBody::Payload(vec![1, 2, 3]))
//                             },
//                             storage::packet::DataBody::KeepAlive(body) => {
//                                 println!("server handle keepalive owd {} sid {}", body.owd(), req.sid);
//                                 Response::None
//                             },
//                             storage::packet::DataBody::Disconnect => {
//                                 println!("server handle Disconnect");
//                                 Response::None
//                             }
//                         }
//                     })
//                 }
//             ))
//         ));
// 
//         // [step 1] Client Initial
//         let handshake_body = storage::packet::HandshakeBody {};
//         let (handshake, handshake_state) = storage::packet::Handshake::initial(
//             &handshake_body,
//             client_alg,
//             &client_sk,
//             &psk, 
//             &server_pk
//         )?;
// 
//         handshake_tx.send((handshake, client_sock)).await?;
// 
//         // [step 2] Server Complete
//         let (packet, s) = out_udp_rx.recv().await.unwrap();
// 
// 
//         // [step 3] Client Complete
//         let (handshake_body, transport_state) = match packet {
//             Packet::Handshake(handshake) => handshake.try_decode(handshake_state)?,
//             _ => panic!("unexpected packet")
//         };
//         let sid = match handshake_body {
//             HandshakeBody::Connected { sid, payload } => sid,
//             HandshakeBody::Disconnected(_) => panic!("storage disconnected")
//         };
// 
//         // Transport
//         let packet = storage::packet::DataPacket::from_body(
//             sid,
//             &storage::packet::DataBody::Payload(vec![1, 2, 3]),
//             &transport_state
//         )?;
//         data_tx.send((packet, client_sock)).await?;
// 
//         // Server
//         let (packet, _) = out_udp_rx.recv().await.unwrap();
// 
//         // Client
//         let body = match packet {
//             Packet::Data(data) => data.decrypt(&transport_state)?,
//             _ => panic!("unexpected packet")
//         };
//         match body {
//             DataBody::Payload(bytes) => {
//                 assert_eq!(bytes, vec![1, 2, 3]);
//             },
//             _ => panic!("unexpected body")
//         }
//         Ok(())
// 
// 
//     }
// }