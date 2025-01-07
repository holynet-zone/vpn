use std::io::Write;
use std::thread;
use std::time::Duration;
use mio::net::UdpSocket;
use tracing::{debug, error, info, warn};
use tun::Device;
use sunbeam:: {
    protocol:: {
        body, 
        ServerPacket,
        ClientPacket,
        enc:: {
            BodyEnc, AuthEnc, aes128, aes256, chacha20_poly1305
        },
        bytes::{ ToBytes, FromBytes}
    }
};
use crate::runtime::exceptions::RuntimeError;
use crate::runtime::session::Session;

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

pub fn server_event(
    data: &[u8],
    tun: &mut Device,
    session: &Session
) -> Result<(), RuntimeError> {
    let packet = match dec_by_body(&session.enc, data, &session.key) {
        Some(dec_packet) => match ServerPacket::from_bytes(&dec_packet) {
            Ok(packet) => packet,
            Err(error) => {
                warn!("Failed to deserialize server packet: {}", error);
                return Ok(())
            }
        },
        None => {
            warn!("Failed to decrypt server packet, it might be a trash packet");
            return Ok(())
        }
    };
    
    match packet.0 {
        body::ServerBody::Data(data) => {
            tun.write(&data).map_err(|error| {
                let err_msg = format!("Failed to write data to tun: {}", error);
                error!("{}", &err_msg);
                RuntimeError::IOError(err_msg)
            })?;
            info!("Received {} bytes from the server", data.len());
            Ok(())
        },
        body::ServerBody::KeepAlive { server_ts, client_ts } => {
            let owd = server_ts - client_ts;
            let rtt = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() - client_ts;
   
            info!(
                "Received keep-alive from the server; One-Way Delay (OWD) = {}; Round Trip Time (RTT) = {}",
                if owd > rtt { "N/A".to_string() } else { owd.to_string() },
                rtt
            );
            
            Ok(())
        },
        body::ServerBody::Disconnection(error) => match error {
            body::SDState::ServerShutdown => {
                let err_msg = "Server shutdown".to_string();
                error!("{}", &err_msg);
                Err(RuntimeError::ServerShutdown(err_msg))
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
        body: enc_by_body(
            &session.enc, 
            &body::ClientBody::Data(data.to_vec()).to_bytes().unwrap(), 
            &session.key
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
    username: &str,
    auth_key: &[u8],
    auth_enc: &AuthEnc,
    body_enc: &BodyEnc,
) -> Result<body::Setup, RuntimeError> {
    let packet = ClientPacket {
        sid: 0,
        body: enc_by_auth(
            auth_enc,
            &body::ClientBody::Connection { enc: body_enc.clone() }.to_bytes().unwrap(),
            auth_key
        ),
        buffer: username.as_bytes().to_vec()
    };
    
    info!("Sending connection request to the server");
    socket.send(&packet.to_bytes().unwrap()).map_err(|error| {
        let err_msg = format!("Failed to send connection request: {}", error);
        error!("{}", &err_msg);
        RuntimeError::IOError(err_msg)
    })?;
    thread::sleep(Duration::from_secs(1));
    let mut buffer = [0u8; super::UDP_BUFFER_SIZE];
    let n = socket.recv(&mut buffer).map_err(|error| {
        let err_msg = format!("Failed to receive connection response: {}", error);
        error!("{}", &err_msg);
        RuntimeError::IOError(err_msg)
    })?;
    
    let server_packet = match dec_by_auth(auth_enc, &buffer[0..n], auth_key) {
        Some(server_packet) => match ServerPacket::from_bytes(&server_packet) {
            Ok(server_packet) => server_packet,
            Err(error) => {
                let err_msg = format!("Failed to deserialize connection response: {}", error);
                error!("{}", &err_msg);
                return Err(RuntimeError::UnexpectedError(err_msg));
            }
        },
        // If the login parameters are incorrect or there is a packet format error, 
        // the message may not be encrypted!
        None => match ServerPacket::from_bytes(&buffer[0..n]) {
            Ok(server_packet) => server_packet,
            Err(_) =>  return Err(
                RuntimeError::InvalidCredentials("Failed to decrypt connection response".to_string())
            )
        }
    };

    match server_packet.0 {
        body::ServerBody::Connection(setup) => {
            info!("Successfully connected to the server");
            Ok(setup)
        },
        body::ServerBody::Disconnection(error) => match error {
            body::SDState::MaxConnectedDevices(count) => {
                let err_msg = format!("Max connected devices: {}", count);
                error!("{}", &err_msg);
                Err(RuntimeError::MaxConnectedDevices(err_msg))
            },
            body::SDState::ServerOverloaded => {
                let err_msg = "Server overloaded".to_string();
                error!("{}", &err_msg);
                Err(RuntimeError::ServerOverloaded(err_msg))
            },
            body::SDState::ServerShutdown => {
                let err_msg = "Server shutdown".to_string();
                error!("{}", &err_msg);
                Err(RuntimeError::ServerShutdown(err_msg)) // todo
            },
            body::SDState::InvalidPacketFormat => {
                let err_msg = "Invalid packet format".to_string();
                error!("{}", &err_msg);
                Err(RuntimeError::UnexpectedError(err_msg))
            },
            body::SDState::InvalidCredentials => {
                let err_msg = "Invalid credentials".to_string();
                error!("{}", &err_msg);
                Err(RuntimeError::InvalidCredentials(err_msg))
            },
        },
        _ => {
            let err_msg = "Unsupported packet response".to_string();
            error!("{}", &err_msg);
            Err(RuntimeError::UnexpectedError(err_msg))
        }
    }
}


pub fn keepalive_event(
    socket: &UdpSocket,
    session: &Session
) -> Result<(), RuntimeError> {
    let packet = ClientPacket {
        sid: session.id,
        body: enc_by_body(
            &session.enc, 
            &body::ClientBody::KeepAlive(
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
            ).to_bytes().unwrap(), 
            &session.key
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