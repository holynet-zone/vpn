use is_root::is_root as lib_is_root;

pub mod net;
pub mod exceptions;
pub mod protocol;

/// Obviously max Ethernet frame size is ~ 1500 bytes
/// 
/// https://en.wikipedia.org/wiki/Ethernet_frame
pub const MAX_ETHERNET_BODY_SIZE: usize = 1500;
pub const MAX_IP_HEADERS_SIZE: u8 = 60;
pub const UDP_HEADERS_SIZE: u8 = 8;

/// Max protocol size - maximum size of data that can be sent in one protocol via udp
pub const MAX_PACKET_SIZE: usize = MAX_ETHERNET_BODY_SIZE - MAX_IP_HEADERS_SIZE as usize - UDP_HEADERS_SIZE as usize;

/// Data size - Maximum number of bytes in the payload, including overhead bits and headers
/// 
/// This value should also be used as the MTU for the tun interface to get the correct payload size.
pub const DATA_SIZE: usize = MAX_PACKET_SIZE - 1;


pub fn is_root() -> bool {
    lib_is_root()
}
