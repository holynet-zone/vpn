use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use etherparse::SlicedPacket;
use log::debug;
use tracing::{info, warn};
use mio::net::UdpSocket;
use tun::{Device, ToAddress};
use common::Body;
use crate::clients::Clients;
use crate::exceptions::ServerExceptions;

pub fn input_event(
    data: &[u8],
    tun: &mut Device,
    udp: &mut UdpSocket,
    client_addr: &SocketAddr,
    clients: Arc<Clients>,
    mtu: usize
) -> Result<(), ServerExceptions> {

    let packet = match Body::from_bytes(data) {
        Ok(packet) => packet,
        Err(error) => {
            return Err(ServerExceptions::BadPacketRequest(
                format!("Failed to deserialize packet: {}", error)
            ));
        }
    };

    match packet {
        Body::ConnectionRequest => {
            info!("Received connection request from {}", client_addr);
            if !clients.is_client(&client_addr.ip()) {
                match clients.add(client_addr.ip(), client_addr.port()) {
                    Some(holy_ip) => {
                        info!("New client connection: {} (local ip: {})", client_addr, holy_ip);
                        let response = Body::ConnectionResponse {
                            status: true,
                            message: "Connected".to_string(),
                            setup: Some(common::Setup {
                                ip: holy_ip,
                                prefix: 24,
                                mtu,
                                dns: Ipv4Addr::new(8, 8, 8, 8)
                            })
                        };
                        let response_bytes = response.to_bytes().unwrap();  // todo: handle unwrap
                        udp.send_to(&response_bytes, *client_addr).unwrap();
                        info!("Client {} connected!", client_addr);
                    },
                    None => {
                        let response = Body::ConnectionResponse {
                            status: false,
                            message: "Server is overloaded".to_string(),
                            setup: None
                        };
                        let response_bytes = response.to_bytes().unwrap();  // todo: handle unwrap
                        udp.send_to(&response_bytes, *client_addr).unwrap();
                        warn!("Failed to add client {}: Server is overloaded", client_addr);
                    }
                }
            } else {
                let client = clients.get_client_by_sock(&client_addr.ip()).unwrap();
                warn!("Client {} is already connected! HolyIp: {}", client_addr, client.holy_ip);
                let response = Body::ConnectionResponse {
                    status: true,
                    message: "Already Connected".to_string(),
                    setup: Some(common::Setup {
                        ip: client.holy_ip,
                        prefix: 24,
                        mtu,
                        dns: Ipv4Addr::new(8, 8, 8, 8)
                    })
                };
                let response_bytes = response.to_bytes().unwrap();  // todo: handle unwrap
                udp.send_to(&response_bytes, *client_addr).unwrap();
            }
        },
        Body::KeepAliveRequest { client_timestamp} => {
            let server_timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
            debug!("Received keep-alive from {}; One-Way Delay (OWD) = {}", client_addr, server_timestamp - client_timestamp);
            let response = Body::KeepAliveResponse {
                server_timestamp,
                client_timestamp
            };
            let response_bytes = response.to_bytes().unwrap();  // todo: handle unwrap
            udp.send_to(&response_bytes, *client_addr).unwrap();
        },
        Body::Data { data } => {
            if !clients.is_client(&client_addr.ip()) {
                return Err(ServerExceptions::BadPacketRequest(
                    format!("Client {} is not connected", client_addr)
                ));
            }
            info!("Received {} bytes from {}", data.len(), client_addr);
            tun.write(&data).unwrap();
        },
        _ => {
            return Err(ServerExceptions::BadPacketRequest(
                "Unsupported packet type".to_string()
            ));
        }
    }
    Ok(())
}

pub fn output_event(
    data: &[u8],
    udp: &mut UdpSocket,
    clients: Arc<Clients>
) -> Result<(), ServerExceptions> {
    info!("Received {} bytes from tun", data.len());
    let packet = Body::Data { data: data.to_vec() };
    
    let ip_packet = match SlicedPacket::from_ip(data) {
        Ok(packet) => match packet.net {
            Some(net) => match net {
                etherparse::InternetSlice::Ipv4(ipv4) => ipv4,
                etherparse::InternetSlice::Ipv6(_) => return Err(ServerExceptions::BadPacketRequest(
                    "IPv6 is not supported".to_string()
                ))
            },
            None => return Err(ServerExceptions::BadPacketRequest(
                "Failed to parse IP packet: missing net headers".to_string()
            ))
        },
        Err(error) => return Err(ServerExceptions::BadPacketRequest(
            format!("Failed to deserialize packet: {}", error)
        ))
    };
    
    let client = match clients.get_client(&ip_packet.header().destination_addr().to_address().unwrap()) {
        Some(client_addr) => client_addr,
        None => return Err(ServerExceptions::BadPacketRequest(
            format!("Client with IP {} not found", ip_packet.header().source_addr())
        ))
    };

    match udp.send_to(&packet.to_bytes().unwrap(), SocketAddr::new(client.sock_ip, client.sock_port)) {
        Err(err) => Err(ServerExceptions::IOError(
            format!("Error sending packet to {}: {}", client.sock_ip, err)
        )),
        Ok(_) => {
            info!("Sent {} bytes to {}:{} (holy client: {})", data.len(), client.sock_ip, client.sock_port, client.holy_ip);
            Ok(())
        }
    }
}
