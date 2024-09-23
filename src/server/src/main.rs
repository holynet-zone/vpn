use std::process;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use log::{error, info, warn};
use mio::{Events, Interest, Poll, Token};
use mio::net::UdpSocket;
use tun::platform::Device;
use common::{Body, DATA_SIZE, is_root, MAX_PACKET_SIZE};

const INTERFACE_NAME: &str = "holynet0";

const UDP: Token = Token(0);
const TUN: Token = Token(1);

fn setup_tun(name: &str, mtu: usize) -> Result<Device, String> {
    let mut config = tun::Configuration::default();
    config.name(name);
    config.address((10, 8, 0, 1));
    config.netmask((255, 255, 255, 0));
    config.mtu(mtu as i32);
    config.up();
    
    let tun_device = tun::create(&config).map_err(|error| {
        format!("Failed to create the TUN device: {}", error)
    })?;
    
    Ok(tun_device)
}

fn start_server(address: &str) {

    let address = address.parse().map_err(|error| {
        error!("Failed to parse the server address: {}", error);
        process::exit(1);
    }).unwrap();

    let mut socket = UdpSocket::bind(address).map_err(|error| {
        error!("Failed to bind the server socket: {}", error);
        process::exit(1);
    }).unwrap();
    let clients: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None)); // todo: change to hashmap
    
    let mut tun = setup_tun(INTERFACE_NAME, DATA_SIZE).map_err(|error| {
        error!("{}", error);
        process::exit(1);
    }).unwrap();
    let tun_raw_fd = tun.as_raw_fd();
    let mut tunfd = mio::unix::SourceFd(&tun_raw_fd);

    info!("Server started on {}", address);

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(1024);
    poll.registry()
        .register(&mut socket, UDP, Interest::READABLE).unwrap();
    poll.registry()
        .register(&mut tunfd, TUN, Interest::READABLE).unwrap();

    let mut udp_buffer = [0u8; MAX_PACKET_SIZE];
    let mut tun_buffer = [0u8; DATA_SIZE];
    
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP => {
                    match socket.recv_from(&mut udp_buffer) {
                        Ok((n, client_addr)) => {
                            // From server
                            let packet = match Body::from_bytes(&udp_buffer[0..n]) {
                                Ok(packet) => packet,
                                Err(error) => {
                                    warn!("Failed to deserialize packet: {}", error);
                                    continue;
                                }
                            };
                            udp_buffer.fill(0);
                            
                            match packet {
                                Body::Data { data } => {
                                    let mut clients_guard = clients.lock().unwrap();
                                    if !clients_guard.is_some() {
                                        info!("New client connected: {}", &client_addr);
                                        clients_guard.replace(client_addr);
                                    }
                                    drop(clients_guard);
                                    info!("Received {} bytes from {}", n, client_addr);
                                    // To TUN
                                    tun.write(&data).unwrap();
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to receive data: {}", e);
                            break; // Todo check if just client error
                        }
                    }
                }
                TUN => {
                    // From TUN
                    let n = tun.read(&mut tun_buffer).unwrap();
                    let packet = Body::Data { data: tun_buffer[0..n].to_vec() };
                    info!("Received {} bytes from TUN", n);
                    tun_buffer.fill(0);
                    
                    let clients_guard = clients.lock().unwrap().clone();
                    let client_addr = match clients_guard {  // todo: extract from udp header
                        Some(client_addr) => client_addr,
                        None => {
                            warn!("No client connected");
                            continue;
                        }
                    };
                    socket.send_to(&packet.to_bytes().unwrap(), client_addr).unwrap();
                }
                _ => unreachable!(),
            }
        }
    }

    
    // // Clean up the tun0 interface when done
    // let output = Command::new("sudo")
    //     .arg("ip")
    //     .arg("link")
    //     .arg("delete")
    //     .arg(INTERFACE_NAME)
    //     .output()
    //     .expect("Failed to execute command to delete TUN interface");
    // 
    // if !output.status.success() {
    //     eprintln!("Failed to delete TUN interface: {}", String::from_utf8_lossy(&output.stderr));
    // }
}


fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));


    if !is_root() {
        error!("This program must be run as root");
        process::exit(1);
    }
    
    start_server("0.0.0.0:34254");
    Ok(())
}
