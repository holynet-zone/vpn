use std::{process, thread};
use std::time::Duration;
use clap::Parser;
use tracing::{debug, error, info};
use server::config::Config;
use server::runtime::error::RuntimeError;
use server::runtime::Runtime;
use crate::storage::{database, Clients};
use shared::{success_err, success_warn};

#[derive(Debug, Parser)]
pub struct StartCmd {
    /// host to listen, ex: 0.0.0.0 or from config
    #[arg(short, long)]
    host: Option<String>,
    /// port to listen, default 26256 or from config
    #[arg(short, long)]
    port: Option<u16>,
    /// interface for merging, default available holynetX or from config
    #[arg(short, long, alias = "interface")]
    iface: Option<String>
}

impl StartCmd {
    pub async fn exec(self, mut config: Config) {
        if let Some(host) = self.host {
            config.general.host = host
        }
        
        if let Some(port) = self.port {
            config.general.port = port;
        }
        
        if let Some(iface) = self.iface {
            config.interface.name = iface;
        }

        if let Err(err) = config.save() {
            success_warn!("cant update configuration: {}", err);
        }

        let clients = match database(&config.general.storage) {
            Ok(db) => match Clients::new(db) {
                Ok(store) => store,
                Err(err) => {
                    success_err!("failed to create client storage: {}\n", err);
                    process::exit(1);
                }
            },
            Err(err) => {
                success_err!("load storage: {}\n", err);
                process::exit(1);
            }
        };

        let mut runtime = match Runtime::from_config(config) {
            Ok(runtime) => runtime,
            Err(err) => {
                success_err!("create runtime: {}\n", err);
                process::exit(1);
            }
        };

        runtime.insert_clients(clients.get_all().await
            .iter()
            .map(|cl| (cl.peer_pk.clone(), cl.psk.clone())).collect());

        let stop_tx = runtime.stop_tx.clone();

        ctrlc::set_handler(move || {
            println!("Ctrl-C received, stopping runtime...");
            match stop_tx.send(RuntimeError::StopSignal) {
                Ok(_) => {
                    debug!("stop signal sent from Ctrl-C handler");
                }
                Err(err) => {
                    debug!("stop signal not sent from Ctrl-C handler: {}", err);
                }
            }
            thread::sleep(Duration::from_secs(1));
            process::exit(0);
        }).expect("error setting Ctrl-C handler");

        if let Err(errors) = runtime.run().await {
            for error in errors {
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
}