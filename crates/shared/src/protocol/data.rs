use serde::{Deserialize, Serialize};
use crate::types::VecU16;

#[derive(Serialize, Deserialize)]
pub enum DataServerBody {
    Payload(VecU16<u8>),
    KeepAlive(u128),
    Disconnect(u8)
}

#[derive(Serialize, Deserialize)]
pub enum DataClientBody {
    Payload(VecU16<u8>),
    KeepAlive(u128),
    Disconnect
}
