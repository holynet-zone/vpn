use std::io::Write;
use std::thread;
use std::time::Duration;
use mio::net::UdpSocket;
use tracing::{debug, error, info, warn};
use tun::Device;
use sunbeam:: {
    protocol:: {
        body::*, 
        ServerPacket,
        ClientPacket,
        bytes::{ ToBytes, FromBytes}
    }
};
use sunbeam::protocol::body::ServerBody;
use sunbeam::protocol::enc::EncAlg;
use sunbeam::protocol::keys::auth::AuthKey;
use sunbeam::protocol::username::Username;
use crate::runtime::exceptions::RuntimeError;
use crate::runtime::session::Session;


pub fn server_event(
    packet: ServerPacket,
    tun: &mut Device,
    session: &Session
) -> Result<(), RuntimeError> {
    let body: ServerBody = match packet.0.disenchant(session.key.clone(), session.enc.clone()) {
        Ok(body) => body,
        Err(err) => {
            warn!("Failed to decrypt server packet: {}", err);
            return Ok(())
        }
    };
    
    match body {
        ServerBody::Data(data) => {
            tun.write(&data).map_err(|error| {
                let err_msg = format!("Failed to write data to tun: {}", error);
                error!("{}", &err_msg);
                RuntimeError::IOError(err_msg)
            })?;
            info!("Received {} bytes from the server", data.len());
            Ok(())
        },
        ServerBody::KeepAlive { server_ts, client_ts } => {
            let owd = server_ts - client_ts;
            let rtt = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() - client_ts;
   
            info!(
                "Received keep-alive from the server; One-Way Delay (OWD) = {}; Round Trip Time (RTT) = {}",
                if owd > rtt { "N/A".to_string() } else { owd.to_string() },
                rtt
            );
            
            Ok(())
        },
        ServerBody::Disconnection(error) => match error {
            ServerDisconnectState::ServerShutdown => {
                Err(RuntimeError::ServerShutdown)
            },
            _ => {
                let err_msg = "Unsupported disconnection error".to_string();
                error!("{}", &err_msg);
                Err(RuntimeError::UnexpectedError(err_msg))
            }
        }, // todo disconnect
        _ => {
            let err_msg = "Unsupported packet response".to_string();
            error!("{}", &err_msg);
            Err(RuntimeError::UnexpectedError(err_msg))
        }
    }
}

pub fn device_event(
    data: &[u8],
    udp: &mut UdpSocket,
    session: &Session
) -> Result<(), RuntimeError> {
    let packet = ClientPacket {
        sid: session.id,
        body: EncBody::enchant(
            ClientBody::Data(data.to_vec()).to_bytes().unwrap(),
            session.key.clone(),
            session.enc.clone()
        ),
        buffer: vec![]
    };
    
    match udp.send(&packet.to_bytes().unwrap()) {
        Err(err) => {
            error!("Failed to send data to the server: {}", err);
            Err(RuntimeError::IOError(err.to_string()))
        },
        Ok(_) => {
            info!("Sent {} bytes to {} via udp", data.len(), udp.local_addr()?);
            Ok(())
        }
    }
}



pub fn auth_event(
    socket: &UdpSocket,
    username: &Username,
    auth_key: &AuthKey,
    body_enc: &EncAlg,
) -> Result<Setup, RuntimeError> {
    let packet = ClientPacket {
        sid: 0,
        body: EncBody::enchant(
            ClientBody::Connection { enc: body_enc.clone() },
            auth_key.clone(),
            EncAlg::Aes256
        ),
        buffer: username.as_slice().to_vec()
    };
    
    info!("Sending connection request to the server");
    socket.send(&packet.to_bytes().unwrap()).map_err(|error| {
        RuntimeError::IOError(format!("Failed to send connection request: {}", error))
    })?;
    thread::sleep(Duration::from_secs(1));
    let mut buffer = [0u8; super::UDP_BUFFER_SIZE];
    let n = socket.recv(&mut buffer).map_err(|error| {
        RuntimeError::IOError(format!("Failed to receive connection response: {}", error))
    })?;
    
    let server_packet = ServerPacket::from_bytes(&buffer[0..n]).map_err(|err| {
        return RuntimeError::UnexpectedError(format!("Failed to deserialize connection response: {}", err))
    })?;
    
    let body: ServerBody = match server_packet.0.disenchant(auth_key.clone(), EncAlg::Aes256) {
        Ok(body) => body,
        Err(err) => return match ServerBody::from_bytes(&server_packet.0) {
            Ok(body) => match body {
                ServerBody::Disconnection(err) => match err {
                    ServerDisconnectState::InvalidCredentials => Err(RuntimeError::InvalidCredentials("Invalid username or key".to_string())),
                    ServerDisconnectState::MaxConnectedDevices(count) => Err(RuntimeError::MaxConnectedDevices(count.to_string())),
                    ServerDisconnectState::ServerOverloaded => Err(RuntimeError::ServerOverloaded),
                    ServerDisconnectState::InvalidPacketFormat => Err(RuntimeError::UnexpectedError("Invalid packet format".to_string())),
                    ServerDisconnectState::ServerShutdown => Err(RuntimeError::ServerShutdown)
                },
                _ => Err(RuntimeError::UnexpectedError("Unexpected server packet: Error packet expected".to_string()))
            },
            Err(_) => Err(RuntimeError::UnexpectedError(format!("Cant decode server body: {}", err)))
        }
    };

    match body {
        ServerBody::Connection(setup) => {
            info!("Successfully connected to the server");
            Ok(setup)
        },
        _ => {
            Err(RuntimeError::UnexpectedError("Unsupported packet response".to_string()))
        }
    }
}


pub fn keepalive_event(
    socket: &UdpSocket,
    session: &Session
) -> Result<(), RuntimeError> {
    let packet = ClientPacket {
        sid: session.id,
        body: EncBody::enchant(
            ClientBody::KeepAlive(
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
            ).to_bytes().unwrap(),
            session.key.clone(),
            session.enc.clone()
        ),
        buffer: vec![]
    };
    
    match socket.send(&packet.to_bytes().unwrap()) {
        Err(err) => {
            error!("Failed to send keep-alive to the server: {}", err);
            Err(RuntimeError::IOError(err.to_string()))
        },
        Ok(_) => {
            debug!("Sent keep-alive to the server");
            Ok(())
        }
    }
}