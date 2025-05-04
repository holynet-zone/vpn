use clap::Args;
use std::path::PathBuf;
use std::{process, thread};
use std::time::Duration;
use ctrlc::set_handler;
use tracing::{debug, error, info};
use client::runtime::error::RuntimeError;
use client::runtime::Runtime;
use shared::connection_config::{ConnectionConfig, InterfaceConfig, RuntimeConfig};
use shared::network::find_available_ifname;

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct ConnectCmd {
    /// config file
    #[arg(short, long, value_name = "FILE PATH")]
    config: Option<PathBuf>,
    /// config key
    #[arg(short, long, value_name = "KEY")]
    key: Option<String>
}

impl ConnectCmd {
    pub async fn exec(self) {
        
        let mut config = match self.config {
            Some(ref path) => match ConnectionConfig::load(path) {
                Ok(config) => config,
                Err(err) => {
                    eprintln!("failed to load config: {}", err);
                    process::exit(1);
                }
            },
            None => match self.key {
                Some(key) => match ConnectionConfig::from_base64(&key) {
                    Ok(config) => config,
                    Err(err) => {
                        eprintln!("failed to parse config key: {}", err);
                        process::exit(1);
                    }
                },
                None => unreachable!("config or key is required should protected by clap")
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
                eprintln!("failed to save config: {}", err);
                process::exit(1);
            }
        }

        let runtime = Runtime::new(
            match config.general.host.parse() {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("failed to resolve host: {}", err);
                    process::exit(1);
                }
            },
            config.general.port,
            config.general.alg,
            config.credentials,
            config.runtime.unwrap_or_default(),
            config.interface.unwrap_or_default(),
        );

        let stop_tx = runtime.stop_tx.clone();

        set_handler(move || {
            println!("Ctrl-C received, stopping runtime...");
            match stop_tx.send(RuntimeError::StopSignal) {
                Ok(_) => {
                    debug!("stop signal sent from Ctrl-C handler");
                }
                Err(err) => {
                    debug!("stop signal not sent from Ctrl-C handler: {}", err);
                }
            }
            thread::sleep(Duration::from_secs(2));
            process::exit(0);
        }).expect("error setting Ctrl-C handler");

        if let Err(error) = runtime.run().await {
            match error {
                RuntimeError::StopSignal => {
                    info!("runtime stopped");
                }
                _ => {
                    error!("{}", error);
                }
            }
        }
    }
}