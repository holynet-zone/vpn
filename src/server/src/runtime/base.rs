use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Clone)]
pub struct RuntimeConfig {
    pub server_addr: SocketAddr,
    pub network_ip: IpAddr,
    pub network_prefix: u8,
    pub mtu: u16,
    pub interface_name: String,
    pub event_capacity: usize,
    pub event_timeout: Option<Duration>,
    pub storage_path: String,
}

pub struct Configurable<T> {
    pub config: Option<RuntimeConfig>,
    pub runtime: T,
}

pub trait Run {
    fn run(r: &Configurable<Self>)
    where
        Self: Sized;
}

pub trait Stop {
    fn stop(r: &Configurable<Self>)
    where
        Self: Sized;
}  

pub trait Runtime {
    fn run(&self);
    fn stop(&self);
    fn set_config(&mut self, config: RuntimeConfig);
}

impl<T: Run + Stop> Runtime for Configurable<T> {
    fn run(&self) {
        <T as Run>::run(&self)
    }
    fn stop(&self) {
        <T as Stop>::stop(&self)
    }
    fn set_config(&mut self, config: RuntimeConfig) {
        self.config = Some(config)
    }
}

pub(crate) enum RuntimeState {
    Connected,
    Disconnected,
}

