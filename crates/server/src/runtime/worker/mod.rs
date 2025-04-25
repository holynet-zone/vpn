mod handshake;
mod data;

use std::{
    net::SocketAddr,
    sync::Arc
};
use dashmap::DashMap;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::sync::broadcast::Receiver;
use tracing::{error, info, warn};
use tun_rs::AsyncDevice;
use shared::keys::handshake::{PublicKey, SecretKey};
use crate::runtime::worker::data::{data_tun_executor, data_udp_executor};
use crate::runtime::worker::handshake::handshake_executor;
use super::{
    session::Sessions,
    error::RuntimeError
};
use shared::protocol::{EncryptedData, EncryptedHandshake, Packet};
use shared::session::SessionId;
use crate::network::parse_source;
use super::session::HolyIp;
use crate::config::RuntimeConfig;

pub(crate) async fn create(
    addr: SocketAddr,
    stop_tx: broadcast::Sender<RuntimeError>,
    sessions: Sessions,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sk: SecretKey,
    tun: AsyncDevice,
    worker_id: usize,
    config: RuntimeConfig
) -> Result<(), RuntimeError> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::DGRAM,
        Some(Protocol::UDP)
    )?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    socket.set_recv_buffer_size(config.so_rcvbuf)?;
    socket.set_send_buffer_size(config.so_sndbuf)?;
    socket.bind(&addr.into())?;

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

async fn udp_sender(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    mut out_udp_rx: mpsc::Receiver<(Packet, SocketAddr)>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = out_udp_rx.recv() => match result {
                Some((data, client_addr)) => {
                    if let Err(e) = socket.send_to(&data.to_bytes(), &client_addr).await {
                        warn!("failed to send data to {}: {}", client_addr, e);
                    }
                },
                None => break
            }
        }
    }
}

async fn udp_listener(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    handshake_tx: mpsc::Sender<(EncryptedHandshake, SocketAddr)>,
    data_tx: mpsc::Sender<(SessionId, EncryptedData, SocketAddr)>
) {
    let mut udp_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = socket.recv_from(&mut udp_buffer) => {
                match result {
                    Ok((n, client_addr)) => {
                        if n == 0 {
                            warn!("received UDP packet from {} with 0 bytes, dropping it", client_addr);
                            continue;
                        }
                        if n > 65536 {
                            warn!("received UDP packet from {} larger than 65536 bytes, dropping it", client_addr);
                            continue;
                        }
                        match Packet::try_from(&udp_buffer[..n]) {
                            Ok(packet) => match packet {
                                Packet::HandshakeInitial(handshake) => {
                                    if let Err(e) = handshake_tx.send((handshake, client_addr)).await {
                                        error!("failed to send handshake to executor: {}", e);
                                    }
                                },
                                Packet::DataClient{ sid, encrypted } => {
                                    if let Err(e) = data_tx.send((sid, encrypted, client_addr)).await {
                                        error!("failed to send data to executor: {}", e);
                                    }
                                },
                                _ => {
                                    warn!("received unexpected packet from {}, length {}", client_addr, n);
                                    continue;
                                }
                            },
                            Err(e) => {
                                warn!("failed to parse UDP packet from {}: {}", client_addr, e);
                                continue;
                            }
                        }
                    }
                    Err(e) => warn!("failed to receive udp: {}", e)
                }
            }
        }
    }
}


async fn tun_sender(
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    mut out_tun_rx: mpsc::Receiver<Vec<u8>>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = out_tun_rx.recv() => match result {
                Some(data) => {
                    if let Err(e) = tun.send(&data).await {
                        error!("failed to send data to tun: {}", e);
                        // todo add stop signal
                    }
                },
                None => break
            }
        }
    }
}

async fn tun_listener(
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    data_tun_tx: mpsc::Sender<(Vec<u8>, HolyIp)>
) {
    let mut buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = tun.recv(&mut buffer) => match result {
                Ok(len) => match parse_source(&buffer[..len]) {
                    Ok(ip) => {
                        if let Err(e) = data_tun_tx.send((buffer[..len].to_vec(), ip)).await {
                            error!("failed to send data to tun executor: {}", e);
                        }
                    },
                    Err(e) => {
                        warn!("failed to parse tun packet: {}", e);
                        continue;
                    }
                },
                Err(e) => {
                    error!("failed to receive tun packet: {}", e); // todo add stop signal
                    continue;
                }
            }
        }
    }
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