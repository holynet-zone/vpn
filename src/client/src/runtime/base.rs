use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone)]
pub struct Config {
    pub server_addr: SocketAddr,
    pub client_addr: SocketAddr,
    pub interface_name: String,
    pub event_capacity: usize,
    pub event_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,
}

pub struct Configurable<T> {
    pub config: Option<Config>,
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
    fn set_config(&mut self, config: Config);
}

impl<T: Run + Stop> Runtime for Configurable<T> {
    fn run(&self) {
        <T as Run>::run(&self)
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

