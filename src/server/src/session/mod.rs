use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use sunbeam::protocol::enc::BodyEnc;

mod generators;
pub mod single;
pub mod threaded;
pub mod future;
mod utils;

pub type HolyIp = IpAddr;
pub type SessionId = u32;

#[derive(Clone)]
pub struct Session {
    pub sock_addr: SocketAddr,
    pub holy_ip: HolyIp,
    pub last_seen: Instant,
    pub username: String,
    pub enc: BodyEnc,
    pub key: Vec<u8>
}
