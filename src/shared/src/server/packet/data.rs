use crate::server::packet::keepalive::KeepAliveBody;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DataPacket {
    pub enc_body: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub enum DataBody {
    Payload(Vec<u8>),
    KeepAlive(KeepAliveBody),
    Disconnect(u8)
}