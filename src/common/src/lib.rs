use serde::{Deserialize, Serialize};
use is_root::is_root as lib_is_root;


/// Obviously max Ethernet frame size is ~ 1500 bytes  
/// 
/// https://en.wikipedia.org/wiki/Ethernet_frame
pub const MAX_ETHERNET_BODY_SIZE: usize = 1500;
pub const MAX_IP_HEADERS_SIZE: u8 = 60;
pub const UDP_HEADERS_SIZE: u8 = 8;

/// Max packet size - maximum size of data that can be sent in one packet via udp
pub const MAX_PACKET_SIZE: usize = MAX_ETHERNET_BODY_SIZE - MAX_IP_HEADERS_SIZE as usize - UDP_HEADERS_SIZE as usize;

/// Data size - Maximum number of bytes in the payload, including overhead bits and headers
/// 
/// This value should also be used as the MTU for the tun interface to get the correct payload size.
pub const DATA_SIZE: usize = MAX_PACKET_SIZE - 1;


#[derive(Serialize, Deserialize)]
pub enum Body {
    Data { data: Vec<u8> }
}

impl Body {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(&self).map_err(|error| {
            format!("{}", error)
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|error| {
            format!("{}", error)
        })
    }
}

pub fn is_root() -> bool {
    lib_is_root()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    
}
