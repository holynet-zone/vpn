use crate::session::SessionId;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize, Deserialize)]
pub enum HandshakeResponderBody {
    Complete(HandshakeResponderPayload),
    Disconnect(HandshakeError)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HandshakeResponderPayload {
    pub sid: SessionId,
    pub ipaddr: IpAddr
    // pub dns: Vec<IpAddr>,
}


#[derive(Serialize, Deserialize)]
pub enum HandshakeError {
    /// The server administrator can limit the number of devices from which one can connect using
    /// one cred. By default, this is 10 devices - it is set at the stage of creating a storage
    MaxConnectedDevices(u32),
    /// If the number of available IP addresses or session identifiers has expired, 
    /// the server cannot successfully establish a new connection
    ServerOverloaded,
    // If the structure of the request was violated
    Unexpected(String)
}
