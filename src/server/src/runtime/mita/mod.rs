use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::{process, thread};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use mio::{Events, Interest, Poll, Token};
use mio::net::UdpSocket;
use tracing::{error, info, warn};
use crate::session::single::Sessions;
use crate::runtime::base::{Configurable, Run, Stop};
use tun::{set_ipv4_forwarding, setup_tun};
use sunbeam::protocol;
use sunbeam::protocol::bytes::FromBytes;
use rocksdb::{DB, Options};
use crate::runtime::exceptions::RuntimeError;
use crate::runtime::mita::handlers::device_event;

mod handlers;
mod tun;

const UDP: Token = Token(0);
const TUN: Token = Token(1);
const UDP_BUFFER_SIZE: usize = 65536;
const TUN_BUFFER_SIZE: usize = 65536;


pub struct MitaRunner {
    stop_tx: Arc<Mutex<Sender<RuntimeError>>>,
    stop_rx: Arc<Mutex<Receiver<RuntimeError>>>,
}

impl Run for MitaRunner {
    fn run(runtime: &Configurable<Self>) {
        info!("Starting the Mita runtime");
        let stop_tx = runtime.runtime.stop_tx.clone();
        let stop_rx = runtime.runtime.stop_rx.clone();
        let config = match runtime.config.clone() {
            Some(config) => config,
            None => {
                error!("No configuration provided");
                return;
            }
        };

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        thread::spawn(move || {
            loop {
                if let Some(error) = stop_rx.lock().unwrap().try_recv().ok() {
                    info!("Stopping the Mita runtime");
                    stop_flag_clone.store(true, Ordering::Relaxed);
                    error!("{}", error);
                    break;
                }
                thread::sleep(Duration::from_secs(1));
            }
        });
        thread::spawn(move || {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, config.storage_path).map_err(|error| {
                error!("Failed to open the database: {}", error);
                process::exit(1);
            }).unwrap();

            let mut socket = UdpSocket::bind(config.server_addr).map_err(|error| {
                error!("Failed to bind the server socket: {}", error);
                process::exit(1);
            }).unwrap();
            let mut clients= Sessions::new(&config.network_ip, &config.network_prefix);

            let mut tun = setup_tun(
                &config.interface_name, 
                &config.mtu, 
                &config.network_ip, 
                &config.network_prefix
            ).map_err(|error| {
                error!("{}", error);
                process::exit(1);
            }).unwrap();
            
            let tun_raw_fd = tun.as_raw_fd();
            let mut tunfd = mio::unix::SourceFd(&tun_raw_fd);

            info!("Server started on {}", config.server_addr);
            
            set_ipv4_forwarding(true).unwrap();

            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(config.event_capacity);
            println!("events capacity: {}", events.capacity());
            poll.registry()
                .register(&mut socket, UDP, Interest::READABLE).unwrap();
            poll.registry()
                .register(&mut tunfd, TUN, Interest::READABLE).unwrap();

            let mut udp_buffer = [0u8; UDP_BUFFER_SIZE];
            let mut tun_buffer = [0u8; TUN_BUFFER_SIZE];

            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    info!("SyncMio runtime stopped");
                    break;
                }
                
                poll.poll(&mut events, None).unwrap();
                for event in events.iter() {
                    match event.token() {
                        UDP => {
                            match socket.recv_from(&mut udp_buffer) {
                                Ok((n, client_addr)) => {
                                    match protocol::ClientPacket::from_bytes(&udp_buffer[0..n]) {
                                        Ok(packet) => {
                                            handlers::client_event(
                                                packet,
                                                &mut tun,
                                                &mut socket,
                                                &client_addr,
                                                &mut clients,
                                                config.network_prefix,
                                                &db
                                            ).unwrap_or_else(
                                                |error| stop_tx.lock().unwrap().send(error).unwrap()
                                            );
                                        },
                                        Err(e) => warn!("Failed to deserialize client packet: {}", e)
                                    }
                                }
                                Err(e) => warn!("Failed to receive data: {}", e)
                            }
                            udp_buffer.fill(0)
                        }
                        TUN => {
                            match tun.read(&mut tun_buffer) {
                                Ok(n) => {
                                    device_event(
                                        &tun_buffer[0..n],
                                        &mut socket,
                                        &clients
                                    ).unwrap_or_else(
                                        |error| stop_tx.lock().unwrap().send(error).unwrap()
                                    );
                                },
                                Err(e) => warn!("Failed to receive data: {}", e)
                            }
                            tun_buffer.fill(0)
                        }
                        _ => unreachable!(),
                    }
                }
            }
        });
    }
}

impl Stop for MitaRunner {
    fn stop(runtime: &Configurable<Self>) {
        info!("Stopping the Mita runtime");
        runtime.runtime.stop_tx.lock().unwrap().send(
            RuntimeError::StopSignal
        ).unwrap();
    }
}

pub type Mita = Configurable<MitaRunner>;

impl Mita {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Mita {
            config: None,
            runtime: MitaRunner {
                stop_tx: Arc::new(Mutex::new(tx)),
                stop_rx: Arc::new(Mutex::new(rx)),
            }
        }
    }
}