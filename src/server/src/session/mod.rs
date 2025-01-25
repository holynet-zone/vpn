use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use sunbeam::protocol::enc::EncAlg;
use sunbeam::protocol::keys::session::SessionKey;

mod generators;
pub mod single;
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
    pub enc: EncAlg,
    pub key: SessionKey
}
