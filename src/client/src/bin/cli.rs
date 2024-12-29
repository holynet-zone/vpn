// 
// use crate::network;
// use crate::handlers;
// 
// use std::io::Read;
// use std::process;
// use std::os::fd::AsRawFd;
// use tracing::{error, info, warn};
// use std::net::{IpAddr, SocketAddr};
// use std::time::Duration;
// use libc::sleep;
// use mio::{Events, Interest, Poll, Token};
// use mio::net::UdpSocket as MioUdpSocket;
// use tracing_subscriber::fmt;
// use tracing_subscriber::layer::SubscriberExt;
// use tracing_subscriber::util::SubscriberInitExt;
// use common::{is_root, Body, Setup, MAX_PACKET_SIZE};
// use common::net::setup_tun;
// use common::exceptions::CoreExceptions;
// use crate::handlers::{device_event, server_event};
// use crate::network::DefaultGateway;
// 
// const INTERFACE_NAME: &str = "holynet0";
// const EVENT_CAPACITY: usize = 1024;
// const EVENT_TIMEOUT: Duration = Duration::from_millis(1);
// const KEEPALIVE: Duration = Duration::from_secs(10);
// const UDP: Token = Token(0);
// const TUN: Token = Token(1);
// 
// 
// fn get_setup_data(socket: &MioUdpSocket) -> Result<Setup, String> {
//     info!("Sending connection request to the server");
//     let packet = Body::ConnectionRequest;
//     socket.send(&packet.to_bytes().unwrap()).map_err(|error| {
//         let err_msg = format!("Failed to send connection request: {}", error);
//         error!("{}",&err_msg);
//         err_msg
//     })?;
//     std::thread::sleep(Duration::from_secs(1));
//     let mut buffer = [0u8; MAX_PACKET_SIZE];
//     let n = socket.recv(&mut buffer).map_err(|error| {
//         let err_msg = format!("Failed to receive connection response: {}", error);
//         error!("{}",&err_msg);
//         err_msg
//     })?;
//         
//     match Body::from_bytes(&buffer[0..n]) {
//         Ok(Body::ConnectionResponse { status, message, setup }) => {
//             info!("Successfully connected to the server");
//             if status {
//                 match setup {
//                     Some(setup) => Ok(setup),
//                     None => Err("Server did not send the setup data".to_string())
//                 }
//             } else {
//                 Err(format!("Server rejected the connection: {}", message))
//             }
//         },
//         Ok(_) => {
//             Err("Unexpected packet type".to_string())
//         },
//         Err(error) => {
//             Err(format!("Failed to deserialize connection response: {}", error))
//         }
//     }
// }
// 
// 
// fn connect(server_addr: &SocketAddr) -> Result<(), String> {
//     let client_addr = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0);
// 
//     let mut mio_socket = MioUdpSocket::bind(client_addr).map_err(|error| {
//         let err_msg = format!("Failed to bind the client socket: {}", error);
//         error!("{}",&err_msg);
//         err_msg
//     })?;
// 
//     mio_socket.connect(*server_addr).map_err(|error| {
//         let err_msg = format!("Failed to connect to the server: {}", error);
//         error!("{}",&err_msg);
//         err_msg
//     })?;
//     
//     info!("Connecting to the server {}", server_addr);
//     let setup_data = get_setup_data(&mio_socket).map_err(|error| {
//         error!("{}", error);
//         process::exit(1);
//     }).unwrap();
//     info!("Connected!; client addr: {}", mio_socket.local_addr().unwrap());
// 
//     let mut tun = setup_tun(INTERFACE_NAME, &setup_data.mtu, &setup_data.ip, &setup_data.prefix)?;
//     let tun_raw_fd = tun.as_raw_fd();
//     let mut tunfd = mio::unix::SourceFd(&tun_raw_fd);
//     
//     let gw = DefaultGateway::create(&setup_data.ip, server_addr.ip().to_string().as_str(), true);
// 
//     let mut poll = Poll::new().unwrap();
//     let mut events = Events::with_capacity(EVENT_CAPACITY);
//     let mut last_keepalive = std::time::Instant::now();
//     poll.registry().register(&mut mio_socket, UDP, Interest::READABLE).unwrap();
//     poll.registry().register(&mut tunfd, TUN, Interest::READABLE).unwrap();
// 
//     loop {
//         poll.poll(&mut events, Some(EVENT_TIMEOUT)).unwrap();
//         
//         if last_keepalive.elapsed() > KEEPALIVE {
//             let packet = Body::KeepAliveRequest { client_timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() };
//             mio_socket.send(&packet.to_bytes()?).unwrap();
//             last_keepalive = std::time::Instant::now();
//         }
//         
//         for event in events.iter() {    
//             match event.token() {
//                 UDP => {
//                     let mut buffer = [0u8; MAX_PACKET_SIZE];
//                     match mio_socket.recv(&mut buffer) {
//                         Ok(n) => {
//                             server_event(&buffer[0..n], &mut tun).unwrap_or_else(
//                                 |error| match error {
//                                 CoreExceptions::BadPacketRequest(msg) => warn!("{}", msg),
//                                 _ => unreachable!()
//                             });
//                         }
//                         Err(e) => error!("Error reading from client: {}", e)
//                     }
//                     buffer.fill(0);
//                 }
//                 TUN => {
//                     let mut buffer = [0u8; MAX_PACKET_SIZE];
//                     match tun.read(&mut buffer) {
//                         Ok(n) => {
//                             device_event(&buffer[0..n], &mut mio_socket).unwrap_or_else(
//                                 |error| match error {
//                                 CoreExceptions::BadPacketRequest(msg) => warn!("{}", msg),
//                                 _ => unreachable!()
//                             });
//                         }
//                         Err(error) => warn!("Error reading from tun device: {}", error)
//                     }
//                     buffer.fill(0);
//                 }
//                 _ => unreachable!(),
//             }
//         }
//     }
// }
// 
// fn main() -> std::io::Result<()> {
//     let file_appender = tracing_appender::rolling::daily("../../../../logs", "client.log");
//     let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
//     tracing_subscriber::registry()
//         .with(
//             fmt::layer()
//                 .with_writer(non_blocking)
//                 .with_ansi(false),
//         )
//         .with(fmt::layer().with_ansi(true))
//         .init();
//     log::set_max_level(log::LevelFilter::Info);
// 
//     if !is_root() {
//         error!("This program must be run as root");
//         process::exit(1);
//     }
//     
//     connect(&"188.225.42.71:26256".parse().unwrap()).unwrap();
//     Ok(())
// }

use std::{process, thread};
use tracing::{error};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use client::runtime;
use common::{is_root};

use runtime::base::Runtime;



const INTERFACE_NAME: &str = "holynet0";
const EVENT_CAPACITY: usize = 1024;
const EVENT_TIMEOUT: Duration = Duration::from_millis(1);
const KEEPALIVE: Duration = Duration::from_secs(10);


fn connect(server_addr: &SocketAddr) -> Result<(), String> {
    let mut runtime = runtime::sync_mio::SyncMio::new();
    runtime.set_config(runtime::base::Config {
        server_addr: server_addr.clone(),
        client_addr: SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),
        interface_name: INTERFACE_NAME.to_string(),
        event_capacity: EVENT_CAPACITY,
        event_timeout: Some(EVENT_TIMEOUT),
        keepalive: Some(KEEPALIVE),
    });
    runtime.run();

    thread::sleep(Duration::from_secs(60 * 5));
    runtime.stop();
    Ok(())
}

fn main() -> std::io::Result<()> {
    let file_appender = tracing_appender::rolling::daily("logs", "client.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .with(fmt::layer().with_ansi(true))
        .init();
    log::set_max_level(log::LevelFilter::Info);

    if !is_root() {
        error!("This program must be run as root");
        process::exit(1);
    }

    connect(&"188.225.42.71:26256".parse().unwrap()).unwrap();
    Ok(())
}
