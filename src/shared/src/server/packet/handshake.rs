use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::session::SessionId;

#[derive(Serialize, Deserialize)]
pub struct Handshake {
    pub body: Vec<u8>
}


#[derive(Serialize, Deserialize)]
pub enum HandshakeBody {
    Connected(HandshakePayload),
    Disconnected(HandshakeError)
}

#[derive(Serialize, Deserialize)]
pub struct HandshakePayload {
    pub sid: SessionId,
    pub ipaddr: IpAddr
    // pub dns: Vec<IpAddr>,
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
