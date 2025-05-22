use clap::Args;
use std::path::PathBuf;
use std::{process, thread};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use ctrlc::set_handler;
use tokio::sync::watch;
use tracing::{debug, error, info};
use tun_rs::AsyncDevice;
use client::network::RouteState;
use client::runtime::error::RuntimeError;
use client::runtime::Runtime;
use client::runtime::state::RuntimeState;
use shared::connection_config::{ConnectionConfig, InterfaceConfig, RuntimeConfig};
use shared::network::find_available_ifname;
use shared::success_err;

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct ConnectCmd {
    /// common connection (config or key)
    #[arg(value_name = "CONNECTION")]
    connection: Option<String>,
    /// config file
    #[arg(short, long, value_name = "FILE PATH")]
    config: Option<PathBuf>,
    /// config key
    #[arg(short, long, value_name = "KEY")]
    key: Option<String>
}

impl ConnectCmd {
    pub async fn exec(self) {
        
        let mut config = match self.connection {
            Some(ref connection) => match ConnectionConfig::from_base64(connection) {
                Ok(config) => config,
                Err(parse_key_err) => match ConnectionConfig::load(&PathBuf::from(connection)) {
                    Ok(config) => config,
                    Err(parse_config_err) => {
                        success_err!(
                            "parse connection\n\n\t if this key: {}\n\n\t if this config path: {}\n",
                            parse_key_err,
                            parse_config_err
                        );
                        process::exit(1);
                    }
                }
            },
            None => match self.key {
                Some(key) => match ConnectionConfig::from_base64(&key) {
                    Ok(config) => config,
                    Err(err) => {
                        success_err!("parse config key: {}", err);
                        process::exit(1);
                    }
                },
                None => match self.config {
                    Some(ref path) => match ConnectionConfig::load(path) {
                        Ok(config) => config,
                        Err(err) => {
                            success_err!("load config: {}", err);
                            process::exit(1);
                        }
                    },
                    None => unreachable!("config or key is required should protected by clap")
                }
            }
        };

        if config.runtime.is_none() {
            config.runtime = Some(RuntimeConfig::default());
        }

        if config.interface.is_none() {
            config.interface = Some(InterfaceConfig {
                name: find_available_ifname("holynet"),
                mtu: 1420,
            });
        }

        if let Some(path) = self.config {
            if let Err(err) = config.save(&path) {
                success_err!("save config: {}", err);
                process::exit(1);
            }
        }

        let sock_addr = match config.general.host.parse() {
            Ok(addr) => SocketAddr::new(addr, config.general.port),
            Err(err) => {
                success_err!("resolve host: {}", err);
                process::exit(1);
            }
        };

        let iface_config = config.interface.unwrap_or_default();
        let tun = match shared::tun::setup_tun(
            iface_config.name.clone(),
            iface_config.mtu,
            false,
        ).await {
            Ok(tun) => Arc::new(tun),
            Err(err) => {
                success_err!("setup tun: {}", err);
                process::exit(1);
            }
        };

        let routes = match RouteState::new(sock_addr.ip(), iface_config.name).build()
        {
            Ok(routes) => Arc::new(routes),
            Err(err) => {
                success_err!("setup routes: {}", err);
                process::exit(1);
            }
        };
        let routes_clone = routes.clone();

        let runtime = Runtime::new(
            sock_addr,
            tun.clone(),
            config.general.alg,
            config.credentials,
            config.runtime.unwrap_or_default()
        );

        let state_tx = runtime.state_tx.clone();

        tokio::spawn(tun_service(
            state_tx.clone(),
            tun.clone()
        ));

        set_handler(move || {
            println!("Ctrl-C received, stopping runtime...");
            match state_tx.send(RuntimeState::Error(RuntimeError::StopSignal)) {
                Ok(_) => {
                    debug!("stop signal sent from Ctrl-C handler");
                }
                Err(err) => {
                    debug!("stop signal not sent from Ctrl-C handler: {}", err);
                }
            }
            routes.restore();
            thread::sleep(Duration::from_secs(2));
            process::exit(0);
        }).expect("error setting Ctrl-C handler");

        if let Err(error) = runtime.run().await {
            match error {
                RuntimeError::StopSignal => {
                    info!("runtime stopped");
                }
                _ => {
                    routes_clone.restore();
                    success_err!("{}", error);
                }
            }
        }
    }
}


pub async fn tun_service(
    state_tx: watch::Sender<RuntimeState>,
    tun: Arc<AsyncDevice>,
) {
    let mut state_rx = state_tx.subscribe();
    loop {
        match state_rx.changed().await {
            Ok(_) => {
                debug!("tun service execute");
                let state =  state_rx.borrow().clone();
                match state {
                    RuntimeState::Connected((payload, _)) => {
                        match payload.ipaddr {
                            IpAddr::V4(addr) => {
                                if let Err(err) = tun.set_network_address(addr, 32, None) {
                                    state_tx.send(RuntimeState::Error(RuntimeError::IO(
                                        format!("failed to set ipv4 network address: {}", err)
                                    ))).expect("state_tx channel broken in tun_service");
                                    break;
                                }
                            },
                            IpAddr::V6(addr) => {
                                if let Err(err) = tun.add_address_v6(addr, 128) {
                                    state_tx.send(RuntimeState::Error(RuntimeError::IO(
                                        format!("failed to add ipv6 network address: {}", err)
                                    ))).expect("state_tx channel broken in tun_service");
                                    break;
                                }
                            }
                        }
                    },
                    RuntimeState::Error(_) => {
                        debug!("tun service closed by global error state");
                        break;
                    },
                    _ => {}
                }
            }
            Err(err) => {
                debug!("state_tx channel error in tun service: {}", err);
                break;
            }
        }
    }
}
