use std::{
    net::SocketAddr,
    sync::{
        Arc
    }
};
use etherparse::SlicedPacket;
use log::error;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::sync::broadcast::Receiver;
use tracing::{info, warn};
use tun::ToAddress;
use tun_rs::AsyncDevice;
use sunbeam::protocol::bytes::FromBytes;
use sunbeam::protocol::ClientPacket;
use crate::runtime::lunestra::handlers;
use crate::session::future::Sessions;
use crate::client::future::Clients;
use crate::runtime::exceptions::RuntimeError;
use crate::session::HolyIp;

pub(crate) async fn create(
    local_addr: SocketAddr,
    tun: Arc<AsyncDevice>,
    stop_tx: broadcast::Sender<RuntimeError>,
    sessions: Sessions,
    clients: Clients,
    worker_id: usize 
) -> anyhow::Result<()> {
    info!("Starting Lunestra worker {}", worker_id);
    let socket = Socket::new(
        if local_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        }, 
        Type::DGRAM, 
        Some(Protocol::UDP)
    )?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    socket.set_recv_buffer_size(1024 * 1024 * 1024)?;
    socket.set_send_buffer_size(1024 * 1024 * 1024)?;
    socket.bind(&local_addr.into())?;

    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
    let (in_udp_tx, in_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1000);
    let (in_tun_tx, in_tun_rx) = mpsc::channel::<(Vec<u8>, HolyIp)>(1000);
    let (out_udp_tx, out_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1000);
    let (out_tun_tx, out_tun_rx) = mpsc::channel::<Vec<u8>>(1000);
    

    // Handle incoming UDP packets
    tokio::spawn(incoming_udp_packets(stop_tx.subscribe(), socket.clone(), in_udp_tx));

    // Handle incoming TUN packets
    tokio::spawn(incoming_tun_packets(stop_tx.subscribe(), tun.clone(), in_tun_tx));

    // Handle outgoing UDP packets
    tokio::spawn(outgoing_udp_packets(stop_tx.subscribe(), socket.clone(), out_udp_rx));

    // Handle outgoing TUN packets
    tokio::spawn(outgoing_tun_packets(stop_tx.subscribe(), tun.clone(), out_tun_rx));

    // Handle execution Input UPD output TUN
    tokio::spawn(handle_in_udp_out_tun(
        stop_tx.subscribe(),
        stop_tx.clone(),
        in_udp_rx,
        out_tun_tx,
        out_udp_tx.clone(),
        sessions.clone(),
        clients
    ));
    
    // Handle execution Input TUN output UDP
    tokio::spawn(handle_in_tun_out_udp(
        stop_tx.subscribe(),
        stop_tx.clone(),
        in_tun_rx,
        out_udp_tx.clone(),
        sessions.clone()
    ));
    
    Ok(())
}

async fn handle_in_tun_out_udp(
    mut stop: Receiver<RuntimeError>,
    stop_tx: broadcast::Sender<RuntimeError>,
    mut in_tun_rx: mpsc::Receiver<(Vec<u8>, HolyIp)>,
    out_udp_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    sessions: Sessions
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = in_tun_rx.recv() => match result {
                Some((data, holy_ip)) => {
                    let result = handlers::device_event(
                        data.as_slice(),
                        holy_ip,
                        &out_udp_tx,
                        &sessions
                    ).await;
                    if let Err(e) = result {
                        stop_tx.send(e).unwrap();
                    }
                },
                None => break
            }
        }
    }
}

async fn handle_in_udp_out_tun(
    mut stop: Receiver<RuntimeError>,
    stop_tx: broadcast::Sender<RuntimeError>,
    mut in_udp_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    out_tun_tx: mpsc::Sender<Vec<u8>>,
    out_udp_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    sessions: Sessions,
    clients: Clients
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = in_udp_rx.recv() => match result {
                Some((data, client_addr)) => {
                    let packet = match ClientPacket::from_bytes(&data){
                        Ok(packet) => packet,
                        Err(e) => {
                            warn!("Failed to deserialize client packet: {}", e);
                            continue;
                        }
                    };
                    let result = handlers::client_event(
                        packet,
                        &out_tun_tx,
                        &out_udp_tx,
                        &client_addr,
                        &sessions,
                        &clients,
                    ).await;
                    if let Err(e) = result {
                        stop_tx.send(e).unwrap();
                    }
                },
                None => break
            }
        }
    }
}

async fn outgoing_tun_packets(
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
                        warn!("Failed to send tun data: {}", e);
                    }
                },
                None => break
            }
        }
    }
}

async fn outgoing_udp_packets(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    mut out_udp_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = out_udp_rx.recv() => match result {
                Some((data, client_addr)) => {
                    if let Err(e) = socket.send_to(&data, &client_addr).await {
                        warn!("Failed to send data to {}: {}", client_addr, e);
                    }
                },
                None => break
            }
        }
    }
}

async fn incoming_udp_packets(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    in_udp_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>
) {
    let mut udp_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = socket.recv_from(&mut udp_buffer) => {
                match result {
                    Ok((n, client_addr)) => {
                        if n == 0 {
                            continue;
                        }
                        if n > 65536 {
                            warn!("Received UDP packet from {} larger than 65536 bytes, dropping it", client_addr);
                            continue;
                        }
                        let mut data = Vec::with_capacity(n);
                        data.extend_from_slice(&udp_buffer[..n]);
                        if let Err(e) = in_udp_tx.send((data, client_addr)).await {
                            error!("Failed to send data into in_udp_tx: {}", e);
                        }
                    }
                    Err(e) => warn!("Failed to receive data: {}", e)
                }
                udp_buffer.fill(0)
            }
        }
    }
}


async fn incoming_tun_packets(
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    in_tun_tx: mpsc::Sender<(Vec<u8>, HolyIp)>
) {
    let mut tun_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = tun.recv(&mut tun_buffer) => {
                match result {
                    Ok(n) => {
                        if n == 0 {
                            continue;
                        }
                        let ip_addr = match SlicedPacket::from_ip(&tun_buffer[..n]) {
                            Ok(packet) => match packet.net {
                                Some(net) => match net {
                                    etherparse::InternetSlice::Ipv4(ipv4) => match &ipv4.header().destination_addr().to_address() {
                                        Ok(addr) => addr.clone(),
                                        Err(e) => {
                                            warn!("Failed to parse IP addr from ip packet: {}", e);
                                            continue;
                                        }
                                    }
                                    etherparse::InternetSlice::Ipv6(_) => {
                                        warn!("Ipv6 is not supported");
                                        continue;
                                    }
                                },
                                None => {
                                    warn!("Failed to parse IP packet: missing network layer");
                                    continue;
                                }
                            },
                            Err(error) => {
                                warn!("Failed to parse IP packet: {}", error);
                                continue;
                            }
                        };
                        let mut data = Vec::with_capacity(n);
                        data.extend_from_slice(&tun_buffer[..n]);
                        if let Err(e) = in_tun_tx.send((data, HolyIp::from(ip_addr))).await {
                            error!("Failed to send data into in_tun_tx: {}", e);
                        }
                    }
                    Err(e) => warn!("Failed to receive data: {}", e)
                }
                tun_buffer.fill(0)
            }
        }
    }
}