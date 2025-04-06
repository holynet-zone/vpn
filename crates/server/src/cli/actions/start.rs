use crate::runtime::Runtime;
use crate::storage::{database, Clients};
use crate::{config, network, CONFIG_PATH_ENV};
use std::path::{Path, PathBuf};
use std::{process, thread};
use std::time::Duration;
use shared::network::find_available_ifname;
use crate::runtime::error::RuntimeError;

pub async fn start(
    host: Option<String>,
    port: Option<u16>,
    interface: Option<String>,
    config: Option<PathBuf>
) -> anyhow::Result<()> {
    let (mut config, path) = match config {
        Some(path) => (config::Config::load(&path)?, path),
        None => match std::env::var(CONFIG_PATH_ENV) {
            Ok(path) => (config::Config::load(Path::new(&path)).map_err(|error| {
                println!("loading configuration from env: {}", path);
                anyhow::anyhow!("failed to load configuration from env: {}", error)
            })?, PathBuf::from(path)),
            Err(_) => match Path::new("config.toml").exists() {
                true => (config::Config::load(Path::new("config.toml")).map_err(|error| {
                    println!("loading configuration from file: config.toml");
                    anyhow::anyhow!("failed to load configuration from file: {}", error)
                })?, PathBuf::from("config.toml")),
                false => {
                    println!("no configuration provided, using default config");
                    (config::Config::default(), PathBuf::from("config.toml"))
                }
            }
        }
    };

    if let Some(host) = host {
        config.general.host = host.parse()?;
    }
    if let Some(port) = port {
        config.general.port = port;
    }
    if let Some(interface) = interface {
        config.interface.name = interface;
    } else {
        config.interface.name = find_available_ifname("holynet"); // todo undefined behavior
    }

    if let Err(err) = config.save(path.as_path()) {
        eprintln!("cant update configuration: {}", err);
    }
    
    let clients = Clients::new(database(&*config.general.storage)?);
    let mut runtime = Runtime::from_config(config)?;
    runtime.insert_clients(clients.get_all().await);

    let stop_tx = runtime.stop_tx.clone();

    ctrlc::set_handler(move || {
        println!("Ctrl-C received, stopping runtime...");
        stop_tx.send(RuntimeError::StopSignal).unwrap();
        thread::sleep(Duration::from_secs(1));
        process::exit(0);
    }).expect("error setting Ctrl-C handler");
    
    runtime.run().await.map_err(|error| {
        anyhow::anyhow!("Runtime: {}", error)
    })
}