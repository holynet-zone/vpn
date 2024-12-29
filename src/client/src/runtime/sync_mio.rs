use std::io::Read;
use std::os::fd::AsRawFd;
use std::{process, thread};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;
use tracing::{error, info, warn};
use mio::{Events, Interest, Poll, Token};
use mio::net::UdpSocket as MioUdpSocket;
use common::{Body, Setup, MAX_PACKET_SIZE};
use common::exceptions::CoreExceptions;
use common::net::setup_tun;
use crate::handlers::{device_event, server_event};
use crate::network::DefaultGateway;
use super::base::{Configurable, Run, Stop};

const UDP: Token = Token(0);
const TUN: Token = Token(1);

pub struct SyncMioRunner {
    stop_signal: (Sender<()>, Arc<Mutex<Receiver<()>>>),
}

fn auth(socket: &MioUdpSocket) -> Result<Setup, String> {
    info!("Sending connection request to the server");
    let packet = Body::ConnectionRequest;
    socket.send(&packet.to_bytes().unwrap()).map_err(|error| {
        let err_msg = format!("Failed to send connection request: {}", error);
        error!("{}",&err_msg);
        err_msg
    })?;
    thread::sleep(Duration::from_secs(1));
    let mut buffer = [0u8; MAX_PACKET_SIZE];
    let n = socket.recv(&mut buffer).map_err(|error| {
        let err_msg = format!("Failed to receive connection response: {}", error);
        error!("{}",&err_msg);
        err_msg
    })?;

    match Body::from_bytes(&buffer[0..n]) {
        Ok(Body::ConnectionResponse { status, message, setup }) => {
            info!("Successfully connected to the server");
            if status {
                match setup {
                    Some(setup) => Ok(setup),
                    None => Err("Server did not send the setup data".to_string())
                }
            } else {
                Err(format!("Server rejected the connection: {}", message))
            }
        },
        Ok(_) => {
            Err("Unexpected packet type".to_string())
        },
        Err(error) => {
            Err(format!("Failed to deserialize connection response: {}", error))
        }
    }
}

impl Run for SyncMioRunner {
    fn run(runtime: &Configurable<Self>) {
        info!("Starting the SyncMio runtime");
        let stop_signal = runtime.runtime.stop_signal.1.clone();
        let config = match runtime.config.clone() {
            Some(config) => config,
            None => {
                error!("No configuration provided");
                return;
            }
        };
        thread::spawn(move || {
            let mut mio_socket = MioUdpSocket::bind(config.client_addr).map_err(|error| {
                let err_msg = format!("Failed to bind the client socket: {}", error);
                error!("{}",&err_msg);
                err_msg
            }).unwrap();

            mio_socket.connect(config.server_addr).map_err(|error| {
                let err_msg = format!("Failed to connect to the server: {}", error);
                error!("{}",&err_msg);
                err_msg
            }).unwrap();

            info!("Connecting to the server {}", config.server_addr);
            let setup_data = auth(&mio_socket).map_err(|error| {
                error!("{}", error);
                process::exit(1);
            }).unwrap();
            info!("Connected!; client addr: {}", mio_socket.local_addr().unwrap());

            let mut tun = setup_tun(
                &config.interface_name,
                &setup_data.mtu,
                &setup_data.ip,
                &setup_data.prefix
            ).unwrap();
            let tun_raw_fd = tun.as_raw_fd();
            let mut tunfd = mio::unix::SourceFd(&tun_raw_fd);

            let gw = DefaultGateway::create(
                &setup_data.ip,
                config.server_addr.ip().to_string().as_str(),
                true
            );

            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(config.event_capacity);
            let mut last_keepalive = std::time::Instant::now();
            let mut last_stop_check = std::time::Instant::now();
            poll.registry().register(&mut mio_socket, UDP, Interest::READABLE).unwrap();
            poll.registry().register(&mut tunfd, TUN, Interest::READABLE).unwrap();

            loop {
                poll.poll(&mut events, config.event_timeout).unwrap();
                for event in events.iter() {
                    match event.token() {
                        UDP => {
                            let mut buffer = [0u8; MAX_PACKET_SIZE];
                            match mio_socket.recv(&mut buffer) {
                                Ok(n) => {
                                    server_event(&buffer[0..n], &mut tun).unwrap_or_else(
                                        |error| match error {
                                            CoreExceptions::BadPacketRequest(msg) => warn!("{}", msg),
                                            _ => unreachable!()
                                        });
                                }
                                Err(e) => error!("Error reading from client: {}", e)
                            }
                            buffer.fill(0);
                        }
                        TUN => {
                            let mut buffer = [0u8; MAX_PACKET_SIZE];
                            match tun.read(&mut buffer) {
                                Ok(n) => {
                                    device_event(&buffer[0..n], &mut mio_socket).unwrap_or_else(
                                        |error| match error {
                                            CoreExceptions::BadPacketRequest(msg) => warn!("{}", msg),
                                            _ => unreachable!()
                                        });
                                }
                                Err(error) => warn!("Error reading from tun device: {}", error)
                            }
                            buffer.fill(0);
                        }
                        _ => unreachable!(),
                    }
                }
                
                if let Some(keepalive) = config.keepalive {
                    if last_keepalive.elapsed() > keepalive {
                        let packet = Body::KeepAliveRequest {
                            client_timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH).unwrap()
                                .as_millis()
                        };
                        mio_socket.send(&packet.to_bytes().unwrap()).unwrap();
                        last_keepalive = std::time::Instant::now();
                    }
                }
                
                if last_stop_check.elapsed() > Duration::from_secs(2) {
                    if stop_signal.lock().unwrap().try_recv().is_ok() {
                        info!("SyncMio runtime stopped");
                        break;
                    } else { 
                        last_stop_check = std::time::Instant::now();
                    }
                }
            }
        });
    }
}

impl Stop for SyncMioRunner {
    fn stop(runtime: &Configurable<Self>) {
        info!("Stopping the SyncMio runtime");
        runtime.runtime.stop_signal.0.send(()).unwrap();
    }
}

pub type SyncMio = Configurable<SyncMioRunner>;

impl SyncMio {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        SyncMio {
            config: None,
            runtime: SyncMioRunner {
                stop_signal: (tx, Arc::new(Mutex::new(rx)))
            }
        }
    }
}
