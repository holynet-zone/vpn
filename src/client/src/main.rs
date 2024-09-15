use std::io::{Read, Write};
use std::net::UdpSocket;
use std::process::Command;
use std::thread;
use log::{error, info, warn};
use tun::platform::Device;
use serde::{Deserialize, Serialize};

const INTERFACE_NAME_IN: &str = "holynet0";
const INTERFACE_NAME_OUT: &str = "holynet1";

fn setup_in_tun(name: &str) -> Result<Device, String> {
    let mut config = tun::Configuration::default();
    config.name(name);
    config.address((10, 8, 0, 1));
    config.netmask((255, 255, 255, 0));
    config.up();
    

    let tun_device = tun::create(&config).map_err(|error| {
        let err_msg = format!("Failed to create the TUN device: {}", error);
        error!("{}",&err_msg);
        err_msg
    })?;
    Ok(tun_device)
}

fn setup_out_tun(name: &str) -> Result<Device, String> {
    let mut config = tun::Configuration::default();
    config.name(name);
    config.address((10, 7, 0, 2));
    config.netmask((255, 255, 255, 0));
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
        .arg("10.7.0.1")
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

#[derive(Serialize, Deserialize)]
struct VpnPacket {
    client_id: u8,
    data: Vec<u8>
}

async fn connect(address: &str, client_id: u8) -> Result<(), String> {
    let mut socket = UdpSocket::bind("127.0.0.1:0").map_err(|error| {
        let err_msg = format!("Failed to bind the client socket: {}", error);
        error!("{}",&err_msg);
        err_msg
    })?;
    socket.connect(address).map_err(|error| {
        let err_msg = format!("Failed to connect to the server: {}", error);
        error!("{}",&err_msg);
        err_msg
    })?;

    let mut socket_clone = socket.try_clone().unwrap();

    let mut in_tun_device = setup_in_tun(INTERFACE_NAME_IN)?;
    let mut out_tun_device = setup_out_tun(INTERFACE_NAME_OUT)?;

    info!("Connected to the server {}", address);

    thread::scope(|s| {
        s.spawn(|| {
            let mut buffer = [0u8; 1500];
            loop {
                match out_tun_device.read(&mut buffer) {
                    Ok(n) => {
                        info!("{} Received from the tun device", n);
                        let vpn_packet = VpnPacket {
                            client_id,
                            data: buffer[0..n].to_vec(),
                        };
                        buffer.fill(0);
                        let encoded: Vec<u8> = bincode::serialize(&vpn_packet).unwrap();
                        socket.send(&encoded).unwrap();
                    }
                    Err(error) => {
                        warn!("Error reading from tun device: {}", error);
                        continue;
                    }
                }
            }
        });

        s.spawn(|| {
            let mut buffer = [0u8; 1500];
            loop {
                match socket_clone.recv(&mut buffer) {
                    Ok(n) => {
                        info!("{} Received from the server", n);
                        let vpn_packet: VpnPacket = bincode::deserialize(&buffer[..n]).unwrap();
                        info!("Writing data to tun0");
                        in_tun_device.write(&vpn_packet.data).unwrap();
                    }
                    Err(e) => {
                        error!("Error reading from client: {}", e);
                        continue;
                    }
                }
            }
        });
    });
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    connect("127.0.0.1:34254", 1).await.unwrap();
    Ok(())
}
