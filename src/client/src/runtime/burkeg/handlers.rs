use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info, warn};
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


pub async fn server_event(
    packet: ServerPacket,
    tun: &Sender<Vec<u8>>,
    session: &Session
) -> Result<(), RuntimeError> {
    let body: ServerBody = match packet.0.disenchant(session.key.clone(), session.enc.clone()) { // todo: change disenchant api: use borrow!!!
        Ok(body) => body,
        Err(err) => {
            warn!("Failed to decrypt server packet: {}", err);
            return Ok(())
        }
    };
    
    match body {
        ServerBody::Data(data) => Ok(tun.send(data).await.unwrap()),
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
            _ => Err(RuntimeError::UnexpectedError("Unsupported disconnection error".to_string()))
        },
        _ => Err(RuntimeError::UnexpectedError("Unsupported packet response".to_string()))
    }
}

pub async fn device_event(
    data: Vec<u8>,
    udp: &Sender<Vec<u8>>,
    session: &Session
) {
    let packet = ClientPacket {
        sid: session.id,
        body: EncBody::enchant(
            ClientBody::Data(data),
            session.key.clone(),
            session.enc.clone()
        ),
        buffer: vec![]
    };
    
    udp.send(packet.to_bytes().unwrap()).await.unwrap()
}



pub async fn auth_event(
    udp_sender: &Sender<Vec<u8>>,
    udp_receiver: &mut Receiver<ServerPacket>,
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

    udp_sender.send(packet.to_bytes().unwrap()).await.unwrap();
    let response = tokio::select! {
        response = udp_receiver.recv() => match response {
            Some(response) => response,
            None => return Err(RuntimeError::UnexpectedError(
                "Failed to receive connection response bc channel is closed".to_string())
            )
        },
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            return Err(RuntimeError::TimeoutError("Connection request timed out (5 sec)".to_string()))
        }
    };
    
    let body = match response.0.disenchant(auth_key.clone(), EncAlg::Aes256) {
        Ok(body) => body,
        Err(err) => return match ServerBody::from_bytes(&response.0) {
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
        _ => Err(RuntimeError::UnexpectedError("Unsupported packet response".to_string()))
    }
}


pub async fn keepalive_event(
    udp_sender: &Sender<Vec<u8>>,
    session: &Session
) {
    let packet = ClientPacket {
        sid: session.id,
        body: EncBody::enchant(
            ClientBody::KeepAlive(
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
            ),
            session.key.clone(),
            session.enc.clone()
        ),
        buffer: vec![]
    };
    
    udp_sender.send(packet.to_bytes().unwrap()).await.unwrap()
}