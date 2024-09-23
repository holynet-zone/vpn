use std::io::{Read, Write};
use std::net::SocketAddr;
use std::process::Command;
use std::process;
use std::os::fd::AsRawFd;
use log::{error, info, warn};
use mio::{Events, Interest, Poll, Token};
use mio::net::UdpSocket;
use tun::platform::Device;
use common::{Body, DATA_SIZE, is_root, MAX_PACKET_SIZE};

const INTERFACE_NAME: &str = "holynet1";

const UDP: Token = Token(0);
const TUN: Token = Token(1);


fn setup_tun(name: &str, mtu: usize) -> Result<Device, String> {
    let mut config = tun::Configuration::default();
    config.name(name);
    config.address((10, 8, 0, 2));
    config.netmask((255, 255, 255, 0));
    config.mtu(mtu as i32);
    config.up();

    let tun_device = tun::create(&config).map_err(|error| {
        let err_msg = format!("Failed to create the TUN device: {}", error);
        error!("{}",&err_msg);
        err_msg
    })?;
    
    let route_output = Command::new("ip")
        .arg("route")
        .arg("add")
        .arg("0.0.0.0/0")
        .arg("via")
        .arg("10.8.0.1")
        .arg("dev")
        .arg(name)
        .output()
        .expect("Failed to execute IP ROUTE command");

    if !route_output.status.success() {
        let err_msg = format!("Failed to set route: {}", String::from_utf8_lossy(&route_output.stderr));
        error!("{}",&err_msg);
        return Err(err_msg);
    }

    Ok(tun_device)
}

async fn connect(address: &str) -> Result<(), String> {
    let server_address: SocketAddr = address.parse().map_err(|error| {
        error!("Failed to parse the server address: {}", error);
        process::exit(1);
    }).unwrap();
    
    let mut socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).map_err(|error| {
        let err_msg = format!("Failed to bind the client socket: {}", error);
        error!("{}",&err_msg);
        err_msg
    })?;
    
    socket.connect(server_address).map_err(|error| {
        let err_msg = format!("Failed to connect to the server: {}", error);
        error!("{}",&err_msg);
        err_msg
    })?;
    
    let mut tun = setup_tun(INTERFACE_NAME, DATA_SIZE)?;
    let tun_raw_fd = tun.as_raw_fd();
    let mut tunfd = mio::unix::SourceFd(&tun_raw_fd);

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(1024);
    poll.registry()
        .register(&mut socket, UDP, Interest::READABLE).unwrap();
    poll.registry()
        .register(&mut tunfd, TUN, Interest::READABLE).unwrap();

    info!("Connected to the server {}", address);

    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP => {
                    let mut buffer = [0u8; MAX_PACKET_SIZE];
                    match socket.recv(&mut buffer) {
                        Ok(n) => {
                            info!("{} Received from the server", n);
                            let packet = Body::Data { data: buffer[0..n].to_vec() };
                            info!("Writing data to tun0");
                            tun.write(&packet.to_bytes().unwrap()).unwrap();
                        }
                        Err(e) => {
                            error!("Error reading from client: {}", e);
                            continue;
                        }
                    }
                }
                TUN => {
                    let mut buffer = [0u8; MAX_PACKET_SIZE];
                    match tun.read(&mut buffer) {
                        Ok(n) => {
                            info!("{} Received from the tun device", n);
                            let packet = Body::Data { data: buffer[0..n].to_vec() };
                            buffer.fill(0);
                            socket.send(&packet.to_bytes().unwrap()).unwrap();
                        }
                        Err(error) => {
                            warn!("Error reading from tun device: {}", error);
                            continue;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    if !is_root() {
        error!("This program must be run as root");
        process::exit(1);
    }
    
    connect("92.255.67.65:34254").await.unwrap();
    Ok(())
}
