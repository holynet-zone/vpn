use crate::server::packet::keepalive::KeepAliveBody;
use serde::{Deserialize, Serialize};
use snow::StatelessTransportState;

#[derive(Serialize, Deserialize)]
pub struct DataPacket {
    pub(crate) enc_body: Vec<u8>
}

impl DataPacket {
    pub fn from_body(body: &DataBody, state: &StatelessTransportState) -> anyhow::Result<Self> {
        Ok(Self {
            enc_body: {
                let mut buffer = [0u8; 65536];
                let len = state.write_message(
                    0,
                    &bincode::serialize(body)?,
                    &mut buffer
                )?;
                buffer[..len].to_vec()
            }
        })
    }
    
    
}

#[derive(Serialize, Deserialize)]
pub enum DataBody {
    Payload(Vec<u8>),
    KeepAlive(KeepAliveBody),
    Disconnect(u8)
}