use std::net::SocketAddr;
use std::time::Duration;

use sunbeam::protocol::{
    enc::EncAlg,
    keys::auth::AuthKey,
    username::Username
};



#[derive(Clone)]
pub struct Config {
    pub server_addr: SocketAddr,
    pub client_addr: SocketAddr,
    pub interface_name: String,
    pub mtu: u16,
    pub event_capacity: usize,
    pub event_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,
    pub username: Username,
    pub auth_key: AuthKey,
    pub body_enc: EncAlg
}

pub struct Configurable<T> {
    pub config: Option<Config>,
    pub runtime: T,
}

pub trait Run {
    fn run(r: &mut Configurable<Self>)
    where
        Self: Sized;
}

pub trait Stop {
    fn stop(r: &Configurable<Self>)
    where
        Self: Sized;
}  

pub trait Runtime {
    fn run(&mut self);
    fn stop(&self);
    fn set_config(&mut self, config: Config);
}

impl<T: Run + Stop> Runtime for Configurable<T> {
    fn run(&mut self) {
        <T as Run>::run(self)
    }
    fn stop(&self) {
        <T as Stop>::stop(&self)
    }
    fn set_config(&mut self, config: Config) {
        self.config = Some(config)
    }
}

pub(crate) enum RuntimeState {
    Connected,
    Disconnected,
}

