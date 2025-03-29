use super::session::Sessions;
use crate::client::packet::DataBody;
use std::net::IpAddr;

pub struct Request {
    pub ip: IpAddr,
    pub sid: u32,
    pub sessions: Sessions,
    pub body: DataBody
}