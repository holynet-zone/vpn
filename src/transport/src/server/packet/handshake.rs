use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, StatelessTransportState};
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::session::SessionId;

#[derive(Serialize, Deserialize)]
pub struct Handshake {
    pub(crate) body: Vec<u8>
}

impl Handshake {
    
    pub fn complete(body: &HandshakeBody, mut responder: HandshakeState) -> anyhow::Result<(Handshake, StatelessTransportState)> {
        let mut buffer = [0u8; 65536];
        let len = responder.write_message(&bincode::serialize(body).unwrap(), &mut buffer)?;
        Ok((
            Handshake {
                body: buffer[..len].to_vec() // FIXME: remove copy
            },
            responder.into_stateless_transport_mode()?
        ))
    }
    
}


#[derive(Serialize, Deserialize)]
pub enum HandshakeBody {
    Connected {
        sid: SessionId,
        payload: Vec<u8>
    },
    Disconnected(HandshakeError)
}


#[derive(Serialize, Deserialize)]
pub enum HandshakeError {
    /// The server administrator can limit the number of devices from which one can connect using
    /// one cred. By default, this is 10 devices - it is set at the stage of creating a client
    MaxConnectedDevices(u32),
    /// If the number of available IP addresses or session identifiers has expired, 
    /// the server cannot successfully establish a new connection
    ServerOverloaded,
    // If the structure of the request was violated
    Unexpected(String)
}
