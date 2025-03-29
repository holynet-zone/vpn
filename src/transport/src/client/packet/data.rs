use crate::client::packet::keepalive::KeepAliveBody;
use crate::session::SessionId;
use serde::{Deserialize, Serialize};
use snow::StatelessTransportState;

#[derive(Serialize, Deserialize)]
pub struct DataPacket {
    pub sid: SessionId,
    pub(crate) enc_body: Vec<u8>
}

impl DataPacket {
    pub fn decrypt(&self, state: &StatelessTransportState) -> anyhow::Result<DataBody> {
        let mut buffer = [0u8; 65536];
        state.read_message(0, &self.enc_body, &mut buffer)?;
        bincode::deserialize(&buffer).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Serialize, Deserialize)]
pub enum DataBody {
    Payload(Vec<u8>),
    KeepAlive(KeepAliveBody),
    Disconnect
}
