use crate::session::SessionId;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DataPacket {
    pub sid: SessionId,
    pub enc_body: Vec<u8>
}


#[derive(Serialize, Deserialize)]
pub enum DataBody {
    Payload(Vec<u8>),
    KeepAlive(u128),
    Disconnect
}
