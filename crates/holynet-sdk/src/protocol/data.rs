use serde::{Deserialize, Serialize};
use super::primitives::VecU16;

#[derive(Serialize, Deserialize)]
pub enum DataServerBody {
    Packet(VecU16<u8>),
    /// Contains the client's timestamp
    KeepAlive(u128),
    /// Contains the shutdown initiation code
    Disconnect(u8)
}

#[derive(Serialize, Deserialize)]
pub enum DataClientBody {
    Packet(VecU16<u8>),
    /// Contains timestamp
    KeepAlive(u128)
}
