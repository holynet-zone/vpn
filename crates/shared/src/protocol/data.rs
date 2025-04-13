use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum DataServerBody {
    Payload(Vec<u8>),
    KeepAlive(u128),
    Disconnect(u8)
}

#[derive(Serialize, Deserialize)]
pub enum DataClientBody {
    Payload(Vec<u8>),
    KeepAlive(u128),
    Disconnect
}
