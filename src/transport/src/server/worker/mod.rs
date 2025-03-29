mod handshake;
mod data;

use std::{
    net::SocketAddr,
    sync::Arc
};
use std::future::Future;
use std::pin::Pin;
use dashmap::DashMap;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::sync::broadcast::Receiver;
use tracing::{error, info, warn};
use crate::{client, server};
use crate::client::packet::DataBody;
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::server::packet::{HandshakeError, KeepAliveBody};
use crate::session::SessionId;
use super::{
    request::Request,
    response::Response,
    session::Sessions,
    error::RuntimeError
};


pub(crate) async fn create(
    addr: SocketAddr,
    stop_tx: broadcast::Sender<RuntimeError>,
    sessions: Sessions,
    known_clients: Arc<DashMap<PublicKey, SecretKey>>,
    sk: SecretKey,
    handle: Option<Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>>,
    sender_rx: mpsc::Receiver<(SessionId, server::Response)>,
    worker_id: usize 
) -> anyhow::Result<()> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::DGRAM,
        Some(Protocol::UDP)
    )?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    socket.set_recv_buffer_size(1024 * 1024 * 1024)?;
    socket.set_send_buffer_size(1024 * 1024 * 1024)?;
    socket.bind(&addr.into())?;

    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
    let (out_udp_tx, out_udp_rx) = mpsc::channel::<(server::packet::Packet, SocketAddr)>(1000);
    let (handshake_tx, handshake_rx) = mpsc::channel::<(client::packet::Handshake, SocketAddr)>(1000);
    let (data_tx, data_rx) = mpsc::channel::<(client::packet::DataPacket, SocketAddr)>(1000);


    // Handle incoming UDP packets
    tokio::spawn(udp_listener(stop_tx.subscribe(), socket.clone(), handshake_tx, data_tx));

    // Handle outgoing UDP packets
    tokio::spawn(udp_sender(stop_tx.subscribe(), socket.clone(), out_udp_rx));
    
    // Executors
    tokio::spawn(handshake_executor(
        stop_tx.subscribe(), 
        handshake_rx, 
        out_udp_tx.clone(), 
        known_clients.clone(), 
        sessions.clone(),
        sk
    ));
    tokio::spawn(data_executor(
        stop_tx.subscribe(), 
        data_rx,
        out_udp_tx.clone(),
        sessions.clone(),
        handle
    ));
    
    // Sender
    tokio::spawn(sender_executor(
        stop_tx.subscribe(),
        sender_rx,
        out_udp_tx.clone(),
        sessions.clone()
    ));

    let mut stop_rx = stop_tx.subscribe();
    tokio::select! {
        _ = stop_rx.recv() => info!("worker {} stopping", worker_id)
    }
    
    Ok(())
}


async fn sender_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(SessionId, server::Response)>,
    udp_tx: mpsc::Sender<(server::packet::Packet, SocketAddr)>,
    sessions: Sessions
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((sid, response)) => match sessions.get(&sid).await {
                    Some(session) => match session.state {
                        Some(state) => match response {
                            Response::Data(body) => match server::packet::DataPacket::from_body(&body, &state) {
                                Ok(value) => {
                                    if let Err(e) = udp_tx.send((server::packet::Packet::Data(value), session.sock_addr)).await {
                                        error!("failed to send server resp packet to udp queue: {}", e);
                                    }
                                },
                                Err(e) => {
                                    error!("[{}] failed to encode resp packet: {}", session.sock_addr, e);
                                }
                            },
                            Response::Close => {
                                sessions.release(sid).await;
                                info!("session {} closed by resp handler", sid);
                            },
                            Response::None => {}
                        },
                        None => warn!("received resp packet for session with unset state {}", sid)
                    },
                    None => warn!("received resp packet for unknown session {}", sid)
                },
                None => {
                    error!("sender_executor channel is closed");
                    break
                }
            }
        }
    }
}


async fn udp_sender(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    mut out_udp_rx: mpsc::Receiver<(server::packet::Packet, SocketAddr)>
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
    handshake_tx: mpsc::Sender<(client::packet::Handshake, SocketAddr)>,
    data_tx: mpsc::Sender<(client::packet::DataPacket, SocketAddr)>
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
                        match client::packet::Packet::try_from(&udp_buffer[..n]) {
                            Ok(packet) => match packet {
                                client::packet::Packet::Handshake(handshake) => {
                                    if let Err(e) = handshake_tx.send((handshake, client_addr)).await {
                                        error!("failed to send handshake to executor: {}", e);
                                    }
                                },
                                client::packet::Packet::Data(data) => {
                                    if let Err(e) = data_tx.send((data, client_addr)).await {
                                        error!("failed to send data to executor: {}", e);
                                    }
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
                udp_buffer.fill(0)
            }
        }
    }
}




async fn data_executor(
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<(client::packet::DataPacket, SocketAddr)>,
    udp_tx: mpsc::Sender<(server::packet::Packet, SocketAddr)>,
    sessions: Sessions,
    handler: Option<Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data {
                Some((enc_packet, addr)) => match sessions.get(&enc_packet.sid).await {
                    Some(session) => match session.state {
                        Some(state) => match enc_packet.decrypt(&state) {
                            Ok(body) => {
                                // Handle keepalive packets ========================================
                                match body {
                                    DataBody::KeepAlive(ref body) => {
                                        info!("[{}] received keepalive packet from sid {} owd {}", addr, enc_packet.sid, body.owd());
                                        let resp = server::packet::DataBody::KeepAlive(KeepAliveBody::new(body.client_time));
                                        match server::packet::DataPacket::from_body(&resp, &state) {
                                            Ok(value) => {
                                                if let Err(e) = udp_tx.send((server::packet::Packet::Data(value), addr)).await {
                                                    error!("failed to send server data packet to udp queue: {}", e);
                                                }
                                            },
                                            Err(e) => {
                                                error!("[{}] failed to encode keepalive data packet: {}", addr, e);
                                            }
                                        }
                                    },
                                    _ => {}
                                }
                                // Handle custom ===================================================
                                match handler.as_ref() {
                                    Some(handler) => match handler(Request {
                                            ip: addr.ip(),
                                            sid: enc_packet.sid,
                                            sessions: sessions.clone(),  // arc cloning
                                            body
                                        }).await {
                                        Response::Data(body) => match server::packet::DataPacket::from_body(&body, &state) {
                                            Ok(value) => {
                                                if let Err(e) = udp_tx.send((server::packet::Packet::Data(value), addr)).await {
                                                    error!("failed to send server data packet to udp queue: {}", e);
                                                }
                                            },
                                            Err(e) => {
                                                error!("[{}] failed to encode data packet: {}", addr, e);
                                            }
                                        },
                                        Response::Close => {
                                            sessions.release(enc_packet.sid).await;
                                            info!("session {} closed by handler", enc_packet.sid);
                                        },
                                        Response::None => {}
                                    },
                                    None => warn!("[{}] received data packet for session {} but no handler is set", addr, enc_packet.sid)
                                }
                            },
                            Err(err) => warn!("[{}] failed to decrypt data packet (sid: {}): {}", addr, enc_packet.sid, err)
                        },
                        None => warn!("[{}] received data packet for session with unset state {}", addr, enc_packet.sid)
                    },
                    None => warn!("[{}] received data packet for unknown session {}", addr, enc_packet.sid)
                },
                None => {
                    error!("data_executor channel is closed");
                    break
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use tokio::sync::{
        mpsc,
        broadcast
    };
    use crate::{client, server};
    use crate::keys::handshake::{PublicKey, SecretKey};
    use crate::server::error::RuntimeError;
    use crate::server::packet::{DataBody, Packet};
    use crate::server::response::Response;
    use crate::server::r#mod::{data_executor, handshake_executor};
    use crate::session::Alg;

    #[tokio::test]
    async fn test() -> anyhow::Result<()> {
        let psk = SecretKey::generate_x25519();

        let client_sk = SecretKey::generate_x25519();
        let client_pk = PublicKey::derive_from(client_sk.clone());
        let client_alg = Alg::Aes256;
        let client_sock = SocketAddr::from(([127, 0, 0, 1], 0));

        let server_sk = SecretKey::generate_x25519();
        let server_pk = PublicKey::derive_from(server_sk.clone());

        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

        let (stop_tx, _) = broadcast::channel::<RuntimeError>(1);
        let (out_udp_tx, mut out_udp_rx) = mpsc::channel::<(server::packet::Packet, SocketAddr)>(1000);
        let (handshake_tx, handshake_rx) = mpsc::channel::<(client::packet::Handshake, SocketAddr)>(1000);
        let (data_tx, data_rx) = mpsc::channel::<(client::packet::DataPacket, SocketAddr)>(1000);

        let sessions = server::session::Sessions::new();
        let known_clients = std::sync::Arc::new(dashmap::DashMap::new());
        known_clients.insert(client_pk.clone(), psk.clone());

        // Executors
        println!("exec");

        tokio::spawn(handshake_executor(
            stop_tx.subscribe(),
            handshake_rx,
            out_udp_tx.clone(),
            known_clients.clone(),
            sessions.clone(),
            server_sk
        ));
        tokio::spawn(data_executor(
            stop_tx.subscribe(),
            data_rx,
            out_udp_tx.clone(),
            sessions.clone(),
            Some(
                std::sync::Arc::new(|req| {
                    Box::pin(async move {
                        match req.body {
                            client::packet::DataBody::Payload(bytes) => {
                                println!("server handle {} bytes payload, sid: {}", bytes.len(), req.sid);
                                Response::Data(DataBody::Payload(vec![1, 2, 3]))
                            },
                            client::packet::DataBody::KeepAlive(body) => {
                                println!("server handle keepalive owd {} sid {}", body.owd(), req.sid);
                                Response::None
                            },
                            client::packet::DataBody::Disconnect => {
                                println!("server handle Disconnect");
                                Response::None
                            }
                        }
                    })
                }
            ))
        ));

        // [step 1] Client Initial
        let handshake_body = client::packet::HandshakeBody {};
        let (handshake, handshake_state) = client::packet::Handshake::initial(
            &handshake_body,
            client_alg,
            &client_sk,
            &psk, 
            &server_pk
        )?;

        handshake_tx.send((handshake, client_sock)).await?;

        // [step 2] Server Complete
        let (packet, s) = out_udp_rx.recv().await.unwrap();


        // [step 3] Client Complete
        let (handshake_body, transport_state) = match packet {
            Packet::Handshake(handshake) => handshake.try_decode(handshake_state)?,
            _ => panic!("unexpected packet")
        };
        let sid = match handshake_body {
            server::packet::HandshakeBody::Connected { sid, payload } => sid,
            server::packet::HandshakeBody::Disconnected(_) => panic!("client disconnected")
        };

        // Transport
        let packet = client::packet::DataPacket::from_body(
            sid,
            &client::packet::DataBody::Payload(vec![1, 2, 3]),
            &transport_state
        )?;
        data_tx.send((packet, client_sock)).await?;

        // Server
        let (packet, _) = out_udp_rx.recv().await.unwrap();

        // Client
        let body = match packet {
            Packet::Data(data) => data.decrypt(&transport_state)?,
            _ => panic!("unexpected packet")
        };
        match body {
            DataBody::Payload(bytes) => {
                assert_eq!(bytes, vec![1, 2, 3]);
            },
            _ => panic!("unexpected body")
        }
        Ok(())


    }
}