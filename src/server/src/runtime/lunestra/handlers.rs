use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::{info, warn};
use tokio::sync::mpsc::Sender;
use sunbeam::protocol:: {
    body::{ClientBody, ServerBody, ServerDisconnectState, Setup, EncBody},
    bytes::{ToBytes},
    ClientPacket,
    ServerPacket,
    enc::EncAlg,
    keys::session::SessionKey,
    username::Username
};
use crate::client::future::Clients;
use crate::runtime::exceptions::RuntimeError;
use crate::session::future::Sessions;
use crate::session::HolyIp;

pub async fn client_event(
    packet: ClientPacket,
    tun_sender: &Sender<Vec<u8>>,
    udp_sender: &Sender<(Vec<u8>, SocketAddr)>,
    client_addr: &SocketAddr,
    sessions: &Sessions,
    clients: &Clients
) -> Result<(), RuntimeError> {
    //////////////////////////////////////// AUTHENTICATION ////////////////////////////////////////
    if packet.sid == 0 && packet.buffer.len() != 0 {
        if packet.buffer.len() > Username::SIZE {
            let response_raw = ServerPacket(ServerBody::Disconnection(
                ServerDisconnectState::InvalidPacketFormat
            ).try_into().unwrap()).to_bytes().unwrap();
            udp_sender.send((response_raw, *client_addr)).await
                .map_err(|e| RuntimeError::UnexpectedError(e.to_string()))?;
            warn!("Failed to authenticate client {}: InvalidPacketFormat - username size is invalid", client_addr);
            return Ok(());
        }
        return match clients.get(packet.buffer.as_slice()).await {
            Some(client) => {
                let client_body = match packet.body.disenchant(client.auth_key.clone(), EncAlg::Aes256) {
                    Ok(body) => body,
                    Err(_) => {
                        let response_raw = ServerPacket(ServerBody::Disconnection(
                            ServerDisconnectState::InvalidCredentials
                        ).try_into().unwrap()).to_bytes().unwrap();
                        udp_sender.send((response_raw, *client_addr)).await
                            .map_err(|e| RuntimeError::UnexpectedError(e.to_string()))?;
                        warn!("Failed to authenticate client {}: cant decode body", client_addr);
                        return Ok(());
                    }
                };
                match client_body {
                    ClientBody::Connection { enc } => {
                        let session_key = SessionKey::generate();
                        let (session_id, holy_ip) = match sessions.add(
                            *client_addr,
                            String::from_utf8_lossy(&packet.buffer).to_string(),
                            enc,
                            session_key.clone()
                        ).await {
                            Some((sid, ip)) => (sid, ip),
                            None => {
                                let response = ServerPacket(ServerBody::Disconnection(
                                    ServerDisconnectState::ServerOverloaded
                                ).try_into().unwrap());
                                let response_bytes = response.to_bytes().unwrap();
                                udp_sender.send((response_bytes, *client_addr)).await
                                    .map_err(|e| RuntimeError::UnexpectedError(e.to_string()))?;
                                warn!("Failed to authenticate client {}: ServerOverloaded", client_addr);
                                return Ok(());
                            }
                        };
                        
                        let enc_body = EncBody::enchant(
                            ServerBody::Connection(Setup {
                                ip: holy_ip,
                                prefix: sessions.prefix,
                                sid: session_id,
                                key: session_key.clone(),
                                dns: IpAddr::from(Ipv4Addr::new(8, 8, 8, 8)) // todo
                            }).to_bytes().unwrap(),
                            client.auth_key,
                            EncAlg::Aes256
                        );
                        
                        udp_sender.send((
                            ServerPacket(enc_body).to_bytes().unwrap(),
                            *client_addr
                        )).await.map_err(|e| RuntimeError::UnexpectedError(e.to_string()))?;
                        info!("New client {} authenticated!", client_addr);
                        Ok(())
                    },
                    _ => {
                        let response_raw = ServerPacket(ServerBody::Disconnection(
                            ServerDisconnectState::InvalidPacketFormat
                        ).try_into().unwrap()).to_bytes().unwrap();
                        udp_sender.send((
                            response_raw,
                            *client_addr
                        )).await.map_err(|e| RuntimeError::UnexpectedError(e.to_string()))?;
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
                let response_raw = ServerPacket(ServerBody::Disconnection(
                    ServerDisconnectState::InvalidCredentials
                ).try_into().unwrap()).to_bytes().unwrap();
                udp_sender.send((response_raw, *client_addr)).await
                    .map_err(|e| RuntimeError::UnexpectedError(e.to_string()))?;
                warn!("Failed to authenticate client {}: InvalidCredentials", client_addr);
                Ok(())
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////
    let session = match sessions.get(&packet.sid).await {
        Some(session) => session,
        None => {
            warn!("Failed to process client {}: InvalidSession", client_addr);
            return Ok(());
        }
    };

    let client_body = match packet.body.disenchant(session.key.clone(), session.enc.clone()) {
        Ok(body) => body,
        Err(_) => {
            warn!("Failed to process client {}: InvalidPacketFormat - cant decode body", client_addr);
            return Ok(());
        }
    };
    match client_body {
        ClientBody::KeepAlive(client_ts) => {
            let body = EncBody::enchant(
                ServerBody::KeepAlive {
                    server_ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
                    client_ts
                }.to_bytes().unwrap(),
                session.key,
                session.enc
            );
            udp_sender.send((
                ServerPacket(body).to_bytes().unwrap(),
                *client_addr
            )).await.map_err(|e| RuntimeError::UnexpectedError(e.to_string()))?;
        },
        ClientBody::Data(data)=> {
            tun_sender.send(data).await.map_err(|e| RuntimeError::UnexpectedError(e.to_string()))?;
        },
        _ => {
            warn!("Failed to process client {}: InvalidPacketFormat - unsupported body", client_addr);
        }
    }
    Ok(())
}

pub async fn device_event(
    data: &[u8],
    dest_ip: HolyIp,
    udp_sender: &Sender<(Vec<u8>, SocketAddr)>,
    sessions: &Sessions,
) -> Result<(), RuntimeError> {
    let session = match sessions.get(&dest_ip).await {
        Some(client_addr) => client_addr,
        None => {
            warn!("Failed to process packet: client not found");
            return Ok(());
        }
    };
    
    let body = EncBody::enchant(
        ServerBody::Data(data.to_vec()).to_bytes().unwrap(),
        session.key,
        session.enc
    );
    
    udp_sender.send((
        ServerPacket(body).to_bytes().unwrap(),
        session.sock_addr
    )).await.map_err(|e| RuntimeError::UnexpectedError(e.to_string()))
}
