use crate::network::find_available_ifname;
use crate::runtime;
use crate::runtime::base::Runtime;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use sunbeam::protocol::{
    enc::EncAlg,
    keys::auth::AuthKey,
    password::Password,
    username::Username
};


pub fn connect(
    server_addr: SocketAddr,
    client_addr: Option<SocketAddr>,
    interface_name: Option<String>,
    mtu: u16,
    event_capacity: usize,
    event_timeout: Option<Duration>,
    keepalive: Option<Duration>,
    username: Username,
    mut auth_key: Option<AuthKey>,
    password: Option<Password>,
    body_enc: EncAlg
) -> anyhow::Result<Box<dyn Runtime + Send>> {
    if let Some(password) = password {
        auth_key = Some(AuthKey::derive_from(
            &password.as_slice(),
            &username.as_slice()
        ));
    }
    
    if auth_key.is_none() {
        return Err(anyhow::anyhow!("Invalid auth key"));
    }
    
    let mut runtime = runtime::burkeg::Burkeg::new();
    runtime.set_config(runtime::base::Config {
        server_addr,
        client_addr: client_addr.unwrap_or_else(|| SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0)),
        interface_name: interface_name.unwrap_or_else(|| find_available_ifname("holynet")),
        mtu,
        event_capacity,
        event_timeout,
        keepalive,
        username,
        auth_key: auth_key.unwrap(),
        body_enc
    });
    runtime.run();
    Ok(Box::new(runtime))
}