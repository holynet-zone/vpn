mod handshake;
mod data;

use std::{
    net::SocketAddr,
    sync::Arc
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::broadcast::{Receiver, Sender};
use tracing::{error, info, warn};
use tun_rs::AsyncDevice;
use shared::protocol::{EncryptedData, Packet};
use shared::connection_config::{CredentialsConfig, RuntimeConfig};

use shared::session::Alg;
use shared::tun::setup_tun;
use crate::network::DefaultGateway;
use crate::runtime::worker::data::{data_tun_executor, data_udp_executor, keepalive_sender};
use crate::runtime::worker::handshake::handshake_step;
use super::error::RuntimeError;


pub(crate) async fn create(
    addr: SocketAddr,
    stop_tx: Sender<RuntimeError>,
    cred: CredentialsConfig,
    alg: Alg,
    config: RuntimeConfig
) -> Result<(), RuntimeError> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::DGRAM,
        Some(Protocol::UDP)
    )?;
    socket.set_nonblocking(true)?;
    // socket.set_reuse_port(true)?;
    socket.set_recv_buffer_size(config.so_rcvbuf)?;
    socket.set_send_buffer_size(config.so_sndbuf)?;
    socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0).into())?;
    socket.connect(&addr.into())?;

    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
    let (udp_sender_tx, udp_sender_rx) = mpsc::channel::<Packet>(config.out_udp_buf);
    let (tun_sender_tx, tun_sender_rx) = mpsc::channel::<Vec<u8>>(config.out_tun_buf);
    let (data_udp_tx, data_udp_rx) = mpsc::channel::<EncryptedData>(config.data_udp_buf);
    let (data_tun_tx, data_tun_rx) = mpsc::channel::<Vec<u8>>(config.data_tun_buf);
    
    // Handshake step
    let (handshake_payload, state) = match tokio::spawn(handshake_step(
        socket.clone(),
        cred,
        alg,
        Duration::from_millis(config.handshake_timeout)
    )).await.unwrap() { // todo unwrap
        Ok((p, state)) => (p, Arc::new(state)),
        Err(err) => {
            stop_tx.send(err.clone())?;
            return Err(err);
        }
    };

    // Handle incoming UDP packets
    tokio::spawn(udp_listener(stop_tx.clone(), stop_tx.subscribe(), socket.clone(), data_udp_tx));

    // Handle outgoing UDP packets
    tokio::spawn(udp_sender(stop_tx.clone(), stop_tx.subscribe(), socket.clone(), udp_sender_rx));


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
        "holynet0",
        1500,
        handshake_payload.ipaddr,
        32
    ).await?);

    let mut gw = DefaultGateway::create(
        &handshake_payload.ipaddr,
        addr.ip().to_string().as_str(),
        true
    );

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


    match config.keepalive {
        Some(duration) => {
            info!("starting keepalive sender with interval {:?}", duration);
            tokio::spawn(keepalive_sender(
                stop_tx.clone(),
                stop_tx.subscribe(),
                udp_sender_tx,
                Duration::from_secs(duration),
                state.clone(),
                handshake_payload.sid,
            ));
        },
        None => info!("keepalive sender is disabled")
    }

    let mut stop_rx = stop_tx.subscribe();
    tokio::select! {
        _ = stop_rx.recv() => {
            gw.delete();
            info!("listener stopped")
        }
    }
    
    Ok(())
}

async fn tun_sender(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    mut queue: mpsc::Receiver<Vec<u8>>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = queue.recv() => match result {
                Some(packet) => {
                    if let Err(err) = tun.send(&packet).await {
                        stop_sender.send(RuntimeError::IO(format!("failed to send tun: {}", err))).unwrap();
                    }
                },
                None => break
            }
        }
    }
}

async fn tun_listener(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    queue: mpsc::Sender<Vec<u8>>
) {
    let mut buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = tun.recv(&mut buffer) => match result {
                Ok(n) => {
                    if n == 0 {
                        warn!("received tun packet with 0 bytes, dropping it");
                        continue;
                    }
                    if n > 65536 {
                        warn!("received tun packet larger than 65536 bytes, dropping it (check ur mtu)");
                        continue;
                    }
                    if let Err(err) = queue.send(buffer[..n].to_vec()).await {
                        error!("failed to send data to data_receiver: {}", err);
                    }
                }
                Err(err) => {
                    stop_sender.send(RuntimeError::IO(format!("failed to receive tun: {}",err))).unwrap();
                }
            }
        }
    }
}


async fn udp_sender(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    mut queue: mpsc::Receiver<Packet>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = queue.recv() => match result {
                Some(packet) => {
                    if let Err(err) = socket.send(&packet.to_bytes()).await {
                        stop_sender.send(RuntimeError::IO(format!("failed to send udp: {}", err))).unwrap();
                    }
                },
                None => break
            }
        }
    }
}

async fn udp_listener(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    data_receiver: mpsc::Sender<EncryptedData>
) {
    let mut udp_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = socket.recv(&mut udp_buffer) => match result {
                Ok(n) => {
                    if n == 0 {
                        warn!("received UDP packet with 0 bytes, dropping it");
                        continue;
                    }
                    if n > 65536 {
                        warn!("received UDP packet larger than 65536 bytes, dropping it");
                        continue;
                    }
                    match Packet::try_from(&udp_buffer[..n]) {
                        Ok(packet) => match packet {
                            Packet::DataServer(data) => {
                                if let Err(err) = data_receiver.send(data).await {
                                    error!("failed to send data to data_receiver: {}", err);
                                }
                            },
                            Packet::HandshakeResponder(_) => {
                                warn!("received handshake packet, but expected data packet");
                                continue;
                            },
                            _ => {
                                warn!("received unexpected packet type");
                                continue;
                            }
                        },
                        Err(err) => {
                            warn!("failed to parse UDP packet: {}", err);
                            continue;
                        }
                    }
                }
                Err(err) => {
                    stop_sender.send(RuntimeError::IO(format!("failed to receive udp: {}", err))).unwrap();
                }
            }
        }
    }
}
