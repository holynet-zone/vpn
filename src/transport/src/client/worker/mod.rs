mod handshake;
mod data;

use std::{
    net::SocketAddr,
    sync::Arc
};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::time::Duration;
use anyhow::Error;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::sync::broadcast::Receiver;
use tracing::{error, info, warn};
use crate::server;
use crate::client::credential::Credential;
use crate::client::packet::{DataBody, Packet};
use crate::client::worker::data::{data_receiver, data_sender};
use crate::client::worker::handshake::handshake_step;
use crate::session::{Alg, SessionId};
use super::{
    request::Request,
    response::Response,
    error::RuntimeError
};


pub(crate) async fn create(
    addr: SocketAddr,
    stop_tx: broadcast::Sender<RuntimeError>,
    cred: Credential,
    alg: Alg,
    handshake_timeout: Duration,
    handshake_payload: Vec<u8>,
    on_request: Option<Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>>,
    on_session_created: Option<Arc<dyn Fn(SessionId, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send>> + Send + Sync>>,
    data_sender_rx: mpsc::Receiver<DataBody>,
    data_sender_tx: mpsc::Sender<DataBody>
) -> anyhow::Result<()> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::DGRAM,
        Some(Protocol::UDP)
    )?;
    socket.set_nonblocking(true)?;
    // socket.set_reuse_port(true)?;
    socket.set_recv_buffer_size(1024 * 1024 * 1024)?;
    socket.set_send_buffer_size(1024 * 1024 * 1024)?;
    socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0).into())?;
    socket.connect(&addr.into())?;

    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
    let (udp_sender_tx, udp_sender_rx) = mpsc::channel::<Packet>(1000);
    let (data_receiver_tx, data_receiver_rx) = mpsc::channel::<server::packet::DataPacket>(1000);


    // Handle incoming UDP packets
    tokio::spawn(udp_listener(stop_tx.subscribe(), socket.clone(), data_receiver_tx));

    // Handle outgoing UDP packets
    tokio::spawn(udp_sender(stop_tx.subscribe(), socket.clone(), udp_sender_rx));
    
    // Handshake step
    let (sid, state) = match tokio::spawn(handshake_step(
        socket.clone(),
        cred,
        alg,
        handshake_timeout,
        handshake_payload,
        on_session_created
    )).await? {
        Ok(v) => v,
        Err(err) => {
            stop_tx.send(err.clone())?;
            return Err(Error::from(err));
        }
    };
    
    let state = Arc::new(state);
    
    // Executors
    tokio::spawn(data_receiver(
        stop_tx.clone(),
        stop_tx.subscribe(), 
        data_receiver_rx,
        data_sender_tx.clone(),
        state.clone(),
        on_request
    ));
    
    tokio::spawn(data_sender(
        stop_tx.clone(),
        stop_tx.subscribe(),
        data_sender_rx,
        udp_sender_tx,
        state,
        sid
    ));

    let mut stop_rx = stop_tx.subscribe();
    tokio::select! {
        _ = stop_rx.recv() => info!("listener stopped"),
    }
    
    Ok(())
}

async fn udp_sender(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    mut out_udp_rx: mpsc::Receiver<Packet>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = out_udp_rx.recv() => match result {
                Some(packet) => {
                    if let Err(err) = socket.send(&packet.to_bytes()).await {
                        error!("failed to send data to the server: {}", err);
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
    data_receiver: mpsc::Sender<server::packet::DataPacket>
) {
    let mut udp_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = socket.recv(&mut udp_buffer) => {
                match result {
                    Ok(n) => {
                        if n == 0 {
                            warn!("received UDP packet with 0 bytes, dropping it");
                            continue;
                        }
                        if n > 65536 {
                            warn!("received UDP packet larger than 65536 bytes, dropping it");
                            continue;
                        }
                        match server::packet::Packet::try_from(&udp_buffer[..n]) {
                            Ok(packet) => match packet {
                                server::packet::Packet::Data(data) => {
                                    if let Err(err) = data_receiver.send(data).await {
                                        error!("failed to send data to data_receiver: {}", err);
                                    }
                                },
                                server::packet::Packet::Handshake(_) => {
                                    warn!("received handshake packet, but expected data packet");
                                    continue;
                                },
                            },
                            Err(err) => {
                                warn!("failed to parse UDP packet: {}", err);
                                continue;
                            }
                        }
                    }
                    Err(err) => warn!("failed to receive udp: {}", err)
                }
                udp_buffer.fill(0)
            }
        }
    }
}
