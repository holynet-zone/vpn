use std::io::Read;
use std::os::fd::AsRawFd;
use std::{process, thread};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};
use mio::{Events, Interest, Poll, Token};
use mio::net::UdpSocket as MioUdpSocket;
use sunbeam::protocol::bytes::FromBytes;
use sunbeam::protocol::ServerPacket;
use crate::network::DefaultGateway;
use super::base::{Configurable, Run, Stop};

use crate::runtime::exceptions::RuntimeError;
use crate::runtime::session::Session;

mod handlers;
mod tun;

const UDP: Token = Token(0);
const TUN: Token = Token(1);
const UDP_BUFFER_SIZE: usize = 65536;
const TUN_BUFFER_SIZE: usize = 65536;


pub struct SyncMioRunner {
    stop_tx: Arc<Mutex<Sender<RuntimeError>>>,
    stop_rx: Arc<Mutex<Receiver<RuntimeError>>>,
}

impl Run for SyncMioRunner {
    fn run(runtime: &Configurable<Self>) {
        info!("Starting the SyncMio runtime");
        let stop_tx = runtime.runtime.stop_tx.clone();
        let stop_rx = runtime.runtime.stop_rx.clone();
        let config = match &runtime.config {
            Some(config) => config.clone(),
            None => {
                error!("No configuration provided");
                return;
            }
        };
        let keepalive_flag = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let keepalive_flag_clone = Arc::clone(&keepalive_flag);
        let stop_flag_clone = Arc::clone(&stop_flag);
        let route: Arc<Mutex<Option<DefaultGateway>>> = Arc::new(Mutex::new(None));
        let route_clone = Arc::clone(&route);

        thread::spawn(move || {
            let mut last_keepalive = Instant::now();
            let route = route_clone;
            loop {
                if let Some(error) = stop_rx.lock().unwrap().try_recv().ok() {
                    info!("Stopping the Mita runtime");
                    stop_flag_clone.store(true, Ordering::Relaxed);
                    error!("{}", error);
                    if let Some(gw) = route.lock().unwrap().as_mut() {
                        gw.delete();
                    }
                    thread::sleep(Duration::from_secs(1));
                    break;
                }
                
                if let Some(sec) = config.keepalive {
                    if last_keepalive.elapsed() > sec {
                        keepalive_flag_clone.store(true, Ordering::Relaxed);
                        last_keepalive = Instant::now();
                    }
                }
                
                thread::sleep(Duration::from_secs(1));
            }
        });


        let mut mio_socket = match MioUdpSocket::bind(config.client_addr) {
            Ok(socket) => socket,
            Err(error) => {
                stop_tx.lock().unwrap().send(RuntimeError::IOError(format!("Failed to bind the client socket: {}", error))).unwrap();
                return;
            }
        };

        match mio_socket.connect(config.server_addr) {
            Ok(_) => (),
            Err(error) => {
                stop_tx.lock().unwrap().send(RuntimeError::IOError(format!("Failed to connect to the server: {}", error))).unwrap();
                return;
            }
        }

        info!("Connecting to the server {}", config.server_addr);
        let setup_data = match handlers::auth_event(
            &mio_socket,
            &config.username,
            &config.auth_key,
            &config.body_enc
        ) {
            Ok(data) => data,
            Err(error) => {
                stop_tx.lock().unwrap().send(error).unwrap();
                return;
            }
        };
        let session = Session {
            id: setup_data.sid,
            key: setup_data.key,
            enc: config.body_enc
        };
        info!("Connected!; client addr: {}", mio_socket.local_addr().unwrap());

        let mut tun = tun::setup_tun(
            &config.interface_name,
            &config.mtu,
            &setup_data.ip,
            &setup_data.prefix
        ).unwrap();

        let mut route_guard = route.lock().unwrap();
        *route_guard = Some(DefaultGateway::create(
            &setup_data.ip,
            config.server_addr.ip().to_string().as_str(),
            true
        ));
        drop(route_guard);
        
        thread::spawn(move || {
            let tun_raw_fd = tun.as_raw_fd();
            let mut tunfd = mio::unix::SourceFd(&tun_raw_fd);
            
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(2usize.pow(16));
            poll.registry().register(&mut mio_socket, UDP, Interest::READABLE).unwrap();
            poll.registry().register(&mut tunfd, TUN, Interest::READABLE).unwrap();
            
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    info!("SyncMio runtime stopped");
                    break;
                }
                
                if keepalive_flag.load(Ordering::Relaxed) {
                    keepalive_flag.store(false, Ordering::Relaxed);
                    handlers::keepalive_event(&mio_socket, &session).unwrap_or_else(
                        |error| stop_tx.lock().unwrap().send(error).unwrap()
                    );
                }
                
                poll.poll(&mut events, None).unwrap();
                 for event in events.iter() {
                    match event.token() {
                        UDP => {
                            let mut buffer = [0u8; UDP_BUFFER_SIZE];
                            match mio_socket.recv(&mut buffer) {
                                Ok(n) => {
                                    let packet = match ServerPacket::from_bytes(&buffer[0..n]) {
                                        Ok(p) => p,
                                        Err(err) => {
                                            warn!("Failed to deserialize server packet: {}", err);
                                            continue
                                        }
                                    };
                                    handlers::server_event(
                                        packet,
                                        &mut tun,
                                        &session
                                    ).unwrap_or_else(
                                        |error| stop_tx.lock().unwrap().send(error).unwrap()
                                    )
                                },
                                Err(e) => error!("Error reading from client: {}", e)
                            }
                            buffer.fill(0);
                        }
                        TUN => {
                            let mut buffer = [0u8; TUN_BUFFER_SIZE];
                            let start = Instant::now();
                            match tun.read(&mut buffer) {
                                Ok(n) => handlers::device_event(
                                    &buffer[0..n], 
                                    &mut mio_socket,
                                    &session
                                ).unwrap_or_else(
                                    |error| stop_tx.lock().unwrap().send(error).unwrap()
                                ),
                                Err(error) => warn!("Error reading from tun device: {}", error)
                            }
                            debug!("TUN event took: {:?}", start.elapsed());
                            buffer.fill(0);
                        }
                        _ => unreachable!(),
                    }
                }
            }
        });
    }
}

impl Stop for SyncMioRunner {
    fn stop(runtime: &Configurable<Self>) {
        runtime.runtime.stop_tx.lock().unwrap().send(
            RuntimeError::StopSignal
        ).unwrap();
    }
}

pub type SyncMio = Configurable<SyncMioRunner>;

impl SyncMio {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        SyncMio {
            config: None,
            runtime: SyncMioRunner {
                stop_tx: Arc::new(Mutex::new(tx)),
                stop_rx: Arc::new(Mutex::new(rx)),
            }
        }
    }
}
