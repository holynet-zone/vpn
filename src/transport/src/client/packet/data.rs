use crate::client::packet::keepalive::KeepAliveBody;
use crate::session::SessionId;
use serde::{Deserialize, Serialize};
use snow::StatelessTransportState;

#[derive(Serialize, Deserialize)]
pub struct DataPacket {
    pub sid: SessionId,
    pub(crate) enc_body: Vec<u8>
}


#[derive(Serialize, Deserialize)]
pub enum DataBody {
    Payload(Vec<u8>),
    KeepAlive(KeepAliveBody),
    Disconnect
}
