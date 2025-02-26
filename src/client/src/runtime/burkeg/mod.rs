use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration};
use tracing::{error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::sync::broadcast::{Receiver, Sender};
use tun_rs::AsyncDevice;
use sunbeam::protocol::bytes::FromBytes;
use sunbeam::protocol::ServerPacket;
use crate::network::DefaultGateway;
use crate::runtime::burkeg::tun::setup_tun;
use super::base::{Configurable, Run, Stop};

use crate::runtime::exceptions::RuntimeError;
use crate::runtime::session::Session;

mod handlers;
mod tun;


pub struct BurkegRunner {
    stop_tx: Option<Sender<RuntimeError>>
}

impl Run for BurkegRunner {
    fn run(runtime: &mut Configurable<Self>) {
        info!("Starting the Burkeg runtime");
        let (stop_tx, mut stop_rx) = broadcast::channel(1);
        runtime.runtime.stop_tx = Some(stop_tx.clone());
        let config = match runtime.config.clone() {
            Some(config) => config,
            None => {
                error!("No configuration provided");
                return;
            }
        };
        
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .unwrap();


            let socket = match rt.block_on(make_socket(config.client_addr)) {
                Ok(socket) => Arc::new(socket),
                Err(error) => {
                    stop_tx.send(RuntimeError::IOError(
                        format!("Failed to create a socket: {}", error))
                    ).unwrap();
                    return;
                }
            };

            info!("Connecting to the server {}", config.server_addr);

            match rt.block_on(socket.connect(config.server_addr)) {
                Ok(_) => (),
                Err(error) => {
                    stop_tx.send(RuntimeError::IOError(
                        format!("Failed to connect to the server: {}", error))
                    ).unwrap();
                    return;
                }
            };

            // udp incoming
            let (incoming_udp_sender, mut udp_receiver) = mpsc::channel::<ServerPacket>(1000);
            rt.spawn(incoming_udp(
                stop_tx.subscribe(),
                Arc::clone(&socket),
                incoming_udp_sender
            ));


            // udp outgoing
            let (udp_sender, outgoing_udp_receiver) = mpsc::channel::<Vec<u8>>(1000);
            rt.spawn(outgoing_udp(
                stop_tx.subscribe(),
                Arc::clone(&socket),
                outgoing_udp_receiver
            ));


            let setup_data = match rt.block_on(handlers::auth_event(
                &udp_sender,
                &mut udp_receiver,
                &config.username,
                &config.auth_key,
                &config.body_enc
            )) {
                Ok(data) => data,
                Err(error) => {
                    stop_tx.send(error).unwrap();
                    return;
                }
            };

            let tun = match rt.block_on(setup_tun(
                &config.interface_name,
                &config.mtu,
                &setup_data.ip,
                &setup_data.prefix
            )) {
                Ok(tun) => Arc::new(tun),
                Err(e) => {
                    stop_tx.send(e).unwrap();
                    return;
                }
            };

            let session = Session {
                id: setup_data.sid,
                key: setup_data.key,
                enc: config.body_enc
            };

            let mut gw = DefaultGateway::create(
                &setup_data.ip,
                config.server_addr.ip().to_string().as_str(),
                true
            );


            // tun incoming
            let (incoming_tun_sender, tun_receiver) = mpsc::channel::<Vec<u8>>(1000);
            rt.spawn(incoming_tun(
                stop_tx.subscribe(),
                Arc::clone(&tun),
                incoming_tun_sender
            ));

            // tun outgoing
            let (tun_sender, outgoing_tun_receiver) = mpsc::channel::<Vec<u8>>(1000);
            rt.spawn(outgoing_tun(
                stop_tx.subscribe(),
                Arc::clone(&tun),
                outgoing_tun_receiver
            ));


            rt.spawn(in_udp_out_tun(
                stop_tx.subscribe(),
                stop_tx.clone(),
                udp_receiver,
                tun_sender,
                session.clone()
            ));

            rt.spawn(in_tun_out_udp(
                stop_tx.subscribe(),
                tun_receiver,
                udp_sender.clone(),
                session.clone()
            ));
            
            rt.spawn(keepalive_sender(
                stop_tx.subscribe(),
                udp_sender,
                config.keepalive.unwrap(),
                session
            ));

            rt.block_on(async move {
                loop {
                    if let Some(error) = stop_rx.recv().await.ok() {
                        error!("Stopping the Burkeg runtime");
                        error!("{}", error);
                        gw.delete();
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        });
    }
}

async fn make_socket(bind_addr: SocketAddr) -> Result<UdpSocket, RuntimeError> {
    let socket = Socket::new(
        if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP)
    ).map_err(|e| RuntimeError::IOError(format!("Failed to create a socket: {}", e)))?;
    
    socket.set_nonblocking(true)?;
    socket.set_recv_buffer_size(1024 * 1024 * 1024)?;
    socket.set_send_buffer_size(1024 * 1024 * 1024)?;
    socket.bind(&bind_addr.into())?;

    Ok(UdpSocket::from_std(socket.into())?)
}

async fn incoming_udp(
    mut stop_signal: Receiver<RuntimeError>, 
    socket: Arc<UdpSocket>, 
    in_udp_sender: mpsc::Sender<ServerPacket>
) {
    let mut udp_buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop_signal.recv() => break,
            result = socket.recv(&mut udp_buffer) => {
                match result {
                    Ok(n) => {
                        if n == 0 {
                            continue;
                        }
                        if n > 65536 {
                            warn!("Received UDP packet from server larger than 65536 bytes, dropping it");
                            continue;
                        }
                        let packet = match ServerPacket::from_bytes(&udp_buffer[0..n]) {
                            Ok(p) => p,
                            Err(err) => {
                                warn!("Failed to deserialize server packet: {}", err);
                                continue
                            }
                        };
                        if let Err(e) = in_udp_sender.send(packet).await {
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

async fn outgoing_udp(
    mut stop: Receiver<RuntimeError>,
    socket: Arc<UdpSocket>,
    mut out_udp_rx: mpsc::Receiver<Vec<u8>>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            result = out_udp_rx.recv() => match result {
                Some(data) => {
                    if let Err(e) = socket.send(&data).await {
                        warn!("Failed to send data to the server: {}", e);
                    }
                },
                None => break
            }
        }
    }
}

async fn outgoing_tun(
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

async fn incoming_tun(
    mut stop: Receiver<RuntimeError>,
    tun: Arc<AsyncDevice>,
    in_tun_tx: mpsc::Sender<Vec<u8>>
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
                        if let Err(e) = in_tun_tx.send(Vec::from(&tun_buffer[..n])).await {
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

async fn in_udp_out_tun(
    mut stop_receiver: Receiver<RuntimeError>,
    stop_sender: Sender<RuntimeError>,
    mut udp_receiver: mpsc::Receiver<ServerPacket>,
    tun_sender: mpsc::Sender<Vec<u8>>,
    sessions: Session
) {
    loop {
        tokio::select! {
            _ = stop_receiver.recv() => break,
            result = udp_receiver.recv() => match result {
                Some(packet) => {
                    let result = handlers::server_event(
                        packet,
                        &tun_sender,
                        &sessions
                    ).await;
                    if let Err(e) = result {
                        stop_sender.send(e).unwrap();
                    }
                },
                None => break
            }
        }
    }
}


async fn in_tun_out_udp(
    mut stop_receiver: Receiver<RuntimeError>,
    mut tun_receiver: mpsc::Receiver<Vec<u8>>,
    udp_sender: mpsc::Sender<Vec<u8>>,
    sessions: Session
) {
    loop {
        tokio::select! {
            _ = stop_receiver.recv() => break,
            result = tun_receiver.recv() => match result {
                Some(data) => handlers::device_event(
                    data,
                    &udp_sender,
                    &sessions
                ).await,
                None => break
            }
        }
    }
}

async fn keepalive_sender(
    mut stop_receiver: Receiver<RuntimeError>,
    udp_sender: mpsc::Sender<Vec<u8>>,
    keepalive_interval: Duration,
    sessions: Session
) {
    let mut interval = tokio::time::interval(keepalive_interval);
    loop {
        tokio::select! {
            _ = stop_receiver.recv() => break,
            _ = interval.tick() => handlers::keepalive_event(&udp_sender,&sessions).await,
        }
    }
}


impl Stop for BurkegRunner {
    fn stop(runtime: &Configurable<Self>) {
        if let Some(tx) = runtime.runtime.stop_tx.clone() {
            tx.send(RuntimeError::StopSignal).unwrap();
        } else {
            error!("Runtime has not yet been launched");
        }
    }
}

pub type Burkeg = Configurable<BurkegRunner>;

impl Burkeg {
    pub fn new() -> Self {
        Self {
            config: None,
            runtime: BurkegRunner {
                stop_tx: None
            }
        }
    }
}
