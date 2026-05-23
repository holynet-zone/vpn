use serde::{Deserialize, Serialize};

/// Bodies encrypted inside a Noise transport message.
/// Use plain Vec<u8> so serde encodes the IP packet directly
/// without an extra bincode-inside-bytes layer.
#[derive(Serialize, Deserialize)]
pub enum DataServerBody {
    Packet(Vec<u8>),
    /// Contains the client's timestamp (microseconds since process start)
    KeepAlive(u128),
    /// Contains the shutdown initiation code
    Disconnect(u8),
}

#[derive(Serialize, Deserialize)]
pub enum DataClientBody {
    Packet(Vec<u8>),
    /// Contains timestamp (microseconds since process start)
    KeepAlive(u128),
}
