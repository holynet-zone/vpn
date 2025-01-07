use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use etherparse::SlicedPacket;
use log::debug;
use tracing::{info, warn};
use mio::net::UdpSocket;
use rocksdb::DB;
use tun::{Device, ToAddress};
use sunbeam::protocol:: {
    body,
    bytes::{FromBytes, ToBytes},
    enc::{AuthEnc, BodyEnc, aes128, aes256, chacha20_poly1305, kdf},
    ClientPacket,
    ServerPacket,
    USERNAME_SIZE,
    SESSION_KEY_SIZE
};
use crate::runtime::exceptions::RuntimeError;
use crate::client::get_client;
use crate::session::single::Sessions;

const SESSION_KEY_TAG: &str = "holynet";


fn enc_by_auth(enc: &AuthEnc, data: &[u8], key: &[u8]) -> Vec<u8> {
    match enc {
        AuthEnc::Aes128 => aes128::encrypt(data, key[0..16].try_into().unwrap()),
        AuthEnc::Aes256 => aes256::encrypt(data, key[0..32].try_into().unwrap()),
        AuthEnc::ChaCha20Poly1305 => chacha20_poly1305::encrypt(data, key[0..32].try_into().unwrap())
    }
}

fn dec_by_auth(enc: &AuthEnc, data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    match enc {
        AuthEnc::Aes128 => aes128::decrypt(data, key[0..16].try_into().unwrap()),
        AuthEnc::Aes256 => aes256::decrypt(data, key[0..32].try_into().unwrap()),
        AuthEnc::ChaCha20Poly1305 => chacha20_poly1305::decrypt(data, key[0..32].try_into().unwrap())
    }
}

fn enc_by_body(enc: &BodyEnc, data: &[u8], key: &[u8]) -> Vec<u8> {
    match enc {
        BodyEnc::Aes128 => aes128::encrypt(data, key[0..16].try_into().unwrap()),
        BodyEnc::Aes256 => aes256::encrypt(data, key[0..32].try_into().unwrap()),
        BodyEnc::ChaCha20Poly1305 => chacha20_poly1305::encrypt(data, key[0..32].try_into().unwrap())
    }
}

fn dec_by_body(enc: &BodyEnc, data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    match enc {
        BodyEnc::Aes128 => aes128::decrypt(data, key[0..16].try_into().unwrap()),
        BodyEnc::Aes256 => aes256::decrypt(data, key[0..32].try_into().unwrap()),
        BodyEnc::ChaCha20Poly1305 => chacha20_poly1305::decrypt(data, key[0..32].try_into().unwrap())
    }
}


pub fn client_event(
    packet: ClientPacket,
    tun: &mut Device,
    udp: &mut UdpSocket,
    client_addr: &SocketAddr,
    sessions: &mut Sessions, 
    prefix: u8,
    user_db: &DB
) -> Result<(), RuntimeError> {
    //////////////////////////////////////// AUTHENTICATION ////////////////////////////////////////
    if packet.sid == 0 && packet.buffer.len() != 0 {
        if packet.buffer.len() > USERNAME_SIZE {
            let response_raw = ServerPacket(body::ServerBody::Disconnection(
                body::SDState::InvalidPacketFormat
            )).to_bytes().unwrap();
            udp.send_to(&response_raw, *client_addr)?;
            warn!("Failed to authenticate client {}: InvalidPacketFormat - username size is invalid", client_addr);
            return Ok(());
        }
        return match get_client(packet.buffer.as_slice(), user_db) {
            Some(client) => {
                let raw_decrypted_body = dec_by_auth(&client.enc, &packet.body, &client.auth_key);
                let raw_deserialized_body = match raw_decrypted_body {
                    Some(packet) => body::ClientBody::from_bytes(&packet),
                    None => {
                        let response_raw = ServerPacket(body::ServerBody::Disconnection(
                            body::SDState::InvalidCredentials
                        )).to_bytes().unwrap();
                        udp.send_to(&response_raw, *client_addr)?;
                        warn!("Failed to authenticate client {}: InvalidCredentials - cant decode body", client_addr);
                        return Ok(());
                    }
                };

                let client_body = match raw_deserialized_body {
                    Ok(body) => body,
                    Err(err) => {
                        let response_raw = ServerPacket(body::ServerBody::Disconnection(
                            body::SDState::InvalidPacketFormat
                        )).to_bytes().unwrap();
                        udp.send_to(&response_raw, *client_addr)?;
                        warn!("Failed to authenticate client {}: InvalidPacketFormat - cant deserialize body", client_addr);
                        debug!("Failed to deserialize body: {:?}", err);
                        return Ok(());
                    }
                };
                match client_body {
                    body::ClientBody::Connection { enc } => {
                        let session_key = match enc {
                            BodyEnc::Aes128 => kdf::derive_random_key(
                                packet.buffer.as_slice(),
                                16,
                                SESSION_KEY_TAG.as_ref()
                            ),
                            BodyEnc::Aes256 | BodyEnc::ChaCha20Poly1305 => kdf::derive_random_key(
                                packet.buffer.as_slice(),
                                32,
                                SESSION_KEY_TAG.as_ref()
                            )
                        };

                        let (session_id, holy_ip) = match sessions.add(
                            *client_addr,
                            String::from_utf8_lossy(&packet.buffer).to_string(), // todo username ascii
                            enc,
                            session_key.clone()
                        ) {
                            Some((sid, ip)) => (sid, ip),
                            None => {
                                let response = ServerPacket(body::ServerBody::Disconnection(
                                    body::SDState::ServerOverloaded
                                ));
                                let response_bytes = response.to_bytes().unwrap();
                                udp.send_to(&response_bytes, *client_addr)?;
                                warn!("Failed to authenticate client {}: ServerOverloaded", client_addr);
                                return Ok(());
                            }
                        };

                        let response_raw = ServerPacket(body::ServerBody::Connection(body::Setup {
                            ip: holy_ip,
                            prefix,
                            sid: session_id,
                            key: {
                                let mut session_key_arr = [0; SESSION_KEY_SIZE];
                                let len = session_key.len().min(SESSION_KEY_SIZE);
                                session_key_arr[..len].copy_from_slice(&session_key[..len]);
                                session_key_arr
                            },
                            dns: IpAddr::from(Ipv4Addr::new(8, 8, 8, 8)) // todo
                        })).to_bytes().unwrap();
                        udp.send_to(
                            &enc_by_auth(&client.enc, &response_raw, &client.auth_key), 
                            *client_addr
                        )?;
                        info!("New client {} authenticated!", client_addr);
                        Ok(())
                    },
                    _ => {
                        let response_raw = ServerPacket(body::ServerBody::Disconnection(
                            body::SDState::InvalidPacketFormat
                        )).to_bytes().unwrap();
                        udp.send_to(
                            &enc_by_auth(&client.enc, &response_raw, &client.auth_key),
                            *client_addr
                        )?;
                        warn!(
                            "Failed to authenticate client {}: InvalidPacketFormat - \
                            The client sent the correct cred, but unsupported body", 
                            client_addr
                        );
                        Ok(())
                    }
                }
            },
            None => {
                let response_raw = ServerPacket(body::ServerBody::Disconnection(
                    body::SDState::InvalidCredentials
                )).to_bytes().unwrap();
                udp.send_to(&response_raw, *client_addr)?;
                warn!("Failed to authenticate client {}: InvalidCredentials", client_addr);
                Ok(())
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////
    let session = match sessions.get(&packet.sid) {
        Some(session) => session,
        None => {
            warn!("Failed to process client {}: InvalidSession", client_addr);
            return Ok(());
        }
    };
   
    let client_body = match dec_by_body(&session.enc, &packet.body, &session.key) {
        Some(packet) => match body::ClientBody::from_bytes(&packet) {
            Ok(body) => body,
            Err(err) => {
                warn!("Failed to process client {}: InvalidPacketFormat - cant deserialize body", client_addr);
                debug!("Failed to deserialize body: {:?}", err);
                return Ok(());
            }
        },
        None => {
            warn!("Failed to process client {}: InvalidCredentials - cant decode body", client_addr);
            return Ok(());
        }
    };
    
    match client_body {
        body::ClientBody::KeepAlive(client_ts) => {
            let server_ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
            let response = ServerPacket(body::ServerBody::KeepAlive {
                server_ts,
                client_ts
            });
            let response_bytes = response.to_bytes().unwrap();
            udp.send_to(&response_bytes, *client_addr)?;
            info!("Received keep-alive from {}; One-Way Delay (OWD) = {}", client_addr, server_ts - client_ts);
        },
        body::ClientBody::Data(data)=> {
            info!("Received {} bytes from {}", data.len(), client_addr);
            tun.write(&data)?;
        },
        _ => {
            warn!("Failed to process client {}: InvalidPacketFormat - unsupported body", client_addr);
        }
    }
    Ok(())
}

pub fn device_event(
    data: &[u8],
    udp: &mut UdpSocket,
    sessions: &Sessions,
) -> Result<(), RuntimeError> {
    info!("Received {} bytes from tun", data.len());
    
    let ip_packet = match SlicedPacket::from_ip(data) {
        Ok(packet) => match packet.net {
            Some(net) => match net {
                etherparse::InternetSlice::Ipv4(ipv4) => ipv4,
                etherparse::InternetSlice::Ipv6(_) => {
                    warn!("Ipv6 is not supported");
                    return Ok(());
                }
            },
            None => {
                warn!("Failed to parse IP packet: missing network layer");
                return Ok(());
            }
        },
        Err(error) => {
            warn!("Failed to parse IP packet: {}", error);
            return Ok(());
        }
    };
    
    let session = match sessions.get(&ip_packet.header().destination_addr().to_address().unwrap()) {
        Some(client_addr) => client_addr,
        None => {
            warn!("Failed to process packet: client not found");
            return Ok(());
        }
    };
    
    let packet_raw = ServerPacket(body::ServerBody::Data(data.to_vec())).to_bytes().unwrap();
    let encrypted_body = enc_by_body(&session.enc, &packet_raw, &session.key);
    match udp.send_to(&encrypted_body, session.sock_addr) {
        Err(err) => {
            warn!("Failed to send packet to {}: {}", session.sock_addr, err);
            Ok(())
        },
        Ok(_) => {
            info!("Sent {} bytes to {} (holy client: {})", data.len(), session.sock_addr, session.holy_ip);
            Ok(())
        }
    }
}
