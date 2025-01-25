use crate::schema::Commands;
use crate::{EVENT_CAPACITY, KEEPALIVE};
use client::actions;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;
use std::{process, thread};
use sunbeam::protocol::enc::EncAlg;
use sunbeam::protocol::keys::auth::AuthKey;
use sunbeam::protocol::password::Password;
use sunbeam::protocol::username::Username;

macro_rules! match_cmd {
    ($value:expr, $pattern:path { .. }) => {
        match $value {
            $pattern { addr, username, auth_key, password, config, key } => (addr, username, auth_key, password, config, key),
        }
    };
}


pub fn connect(cmd: Commands) -> anyhow::Result<()> {
    let (
        addr, 
        username, 
        auth_key, 
        password, 
        config_path, 
        config_key
    ) = match_cmd!(cmd, Commands::Connect { .. });

    if auth_key.is_some() && password.is_some() {
        return Err(anyhow::anyhow!("AuthKey and password cannot be used together"));
    }
    let config = match config_path {
        Some(path) => shared::conn_config::ConnConfig::load(&path).map_err(|error| {
            anyhow::anyhow!("Failed to load config: {}", error)
        })?,
        None => match config_key {
            Some(key) => shared::conn_config::ConnConfig::from_base64(&key).map_err(|error| {
                anyhow::anyhow!("Failed to parse config key: {}", error)
            })?,
            None => {
                
                if addr.is_none() || username.is_none() {
                    return Err(anyhow::anyhow!("addr and username are required"));
                }

                let addr = addr.unwrap();
                let username = Username::try_from(username.unwrap()).map_err(|error| {
                    anyhow::anyhow!("Failed to parse username: {}", error)
                })?;

                let (host, port) = {
                    if let Ok(addr) = SocketAddr::from_str(&addr) {
                        (addr.ip().to_string(), addr.port())
                    } else {
                        let parts: Vec<&str> = addr.split(':').collect();
                        if parts.len() == 2 {
                            let host = parts[0];
                            let port = parts[1].parse::<u16>().map_err(|_| "Invalid port").unwrap();
                            (host.to_string(), port)
                        } else {
                            return Err(anyhow::anyhow!("Invalid address"));
                        }
                    }
                };
                let auth_key = match auth_key {
                    Some(str_key) => AuthKey::try_from(str_key.as_str()).map_err(|error| {
                        anyhow::anyhow!("Failed to parse auth_key: {}", error)
                    })?,
                    None => {
                        if password.is_none() {
                            return Err(anyhow::anyhow!("auth_key or password is required"));
                        }
                        let password = Password::from(password.unwrap());
                        AuthKey::derive_from(
                            password.as_slice(),
                            username.as_slice()
                        )
                    }
                };
                shared::conn_config::ConnConfig {
                    server: shared::conn_config::Server {
                        host,
                        port,
                        enc: EncAlg::Aes256,
                    },
                    interface: shared::conn_config::Interface {
                        name: None,
                        mtu: 1400,
                    },
                    credentials: shared::conn_config::Credentials {
                        username,
                        auth_key
                    },
                }
            }
        }
    };

    let server_addr = match format!("{}:{}", config.server.host, config.server.port)
        .to_socket_addrs()?.next()
    {
        Some(addr) => addr,
        None => {
            return Err(anyhow::anyhow!("Failed to resolve the server address"));
        }
    };

    let runtime = actions::runtime::connect(
        server_addr,
        None,
        config.interface.name,
        config.interface.mtu,
        EVENT_CAPACITY,
        None,
        Some(KEEPALIVE),
        config.credentials.username,
        Some(config.credentials.auth_key),
        None,
        config.server.enc,
    ).map_err(|error| {
        eprintln!("Failed to connect: {}", error);
        process::exit(1);
    }).unwrap();


    ctrlc::set_handler(move || {
        runtime.stop();
        thread::sleep(Duration::from_secs(5));
        process::exit(0);
    }).expect("Error setting Ctrl-C handler");
    thread::park();
    
    Ok(())
}