use std::{process, thread};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, warn};
use crate::{config, network, runtime, CONFIG_PATH_ENV, STORAGE_PATH_ENV};
use crate::runtime::base::{Runtime, RuntimeConfig};

pub fn start(
    host: Option<String>,
    port: Option<u16>,
    iface: Option<String>,
    config: Option<PathBuf>,
    storage: Option<PathBuf>,
    daemon: bool
) {
    if daemon {
        unimplemented!("Daemon mode is not implemented");
    }
    // todo logs for daemon

    let mut need_save_cfg = false;
    let mut config = match config {
        Some(path) => config::Config::load(path.to_str().unwrap()).map_err(|error| {
            error!("Failed to load configuration ({:?}): {}", path, error);
            process::exit(1);
        }).unwrap(),
        None => match std::env::var(CONFIG_PATH_ENV) {
            Ok(dir) => {
                info!("Loading configuration from env: {}", dir);
                config::Config::load(dir.as_str()).map_err(|error| {
                    error!("Failed to load configuration: {}", error);
                    process::exit(1);
                }).unwrap()
            },
            Err(_) => {
                warn!("No configuration provided, using default values");
                need_save_cfg = true;
                config::Config::default()
            }
        }
    };

    if let Some(host) = host {
        config.general.host = host.parse().unwrap();
    }
    if let Some(port) = port {
        config.general.port = port;
    }
    if let Some(iface) = iface {
        config.interface.name = iface;
    } else {
        config.interface.name = network::find_available_ifname("holynet");
    }
    if let Some(storage) = std::env::var(STORAGE_PATH_ENV).ok() {
        config.general.storage_path = storage.into();
    }
    if let Some(storage) = storage {
        config.general.storage_path = storage;
    }

    if need_save_cfg {
        config.save("config.toml").map_err(|error| {
            error!("Failed to save configuration: {}", error);
            process::exit(1);
        }).unwrap();
    }

    let mut runtime = runtime::lunestra::Lunestra::new();
    runtime.set_config(RuntimeConfig{
        server_addr: format!("{}:{}", config.general.host, config.general.port).parse().unwrap(),
        network_ip: config.interface.address,
        network_prefix: config.interface.prefix,
        mtu: config.interface.mtu,
        interface_name: config.interface.name,
        event_capacity: config.runtime.event_capacity as usize,
        event_timeout: config.runtime.event_timeout.map(|timeout| Duration::from_secs(timeout)),
        storage_path: "database".to_string(),
    });
    runtime.run();
    thread::park();
}