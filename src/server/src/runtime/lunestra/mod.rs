use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{error, info};
use crate::session::future::Sessions;
use crate::runtime::base::{Configurable, Run, Stop};
use tun::{set_ipv4_forwarding, setup_tun};
use rocksdb::{Options, DB};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Sender;
use crate::runtime::exceptions::RuntimeError;
use crate::client::future::Clients;

mod handlers;
mod tun;
pub mod worker;


pub struct LunestraRunner {
    stop_tx: Option<Sender<RuntimeError>>
}

impl Run for LunestraRunner {
    fn run(runtime: &mut Configurable<Self>) {
        info!("Starting the Lunestra runtime");
        let (stop_tx, mut stop_rx) = broadcast::channel(1);
        runtime.runtime.stop_tx = Some(stop_tx.clone());
        let config = match runtime.config.clone() {
            Some(config) => config,
            None => {
                error!("No configuration provided");
                return;
            }
        };

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();

            let mut opts = Options::default();
            opts.create_if_missing(true);
            let db = match DB::open(&opts, config.storage_path) {
                Ok(db) => db,
                Err(e) => {
                    stop_tx.send(RuntimeError::UnexpectedError(format!(
                        "Failed to open the database: {}", e
                    ))).unwrap();
                    return;
                }
            };

            let sessions= Sessions::new(&config.network_ip, &config.network_prefix);
            let clients = Clients::new(db);

            let tun = match rt.block_on(setup_tun(
                &config.interface_name,
                &config.mtu,
                &config.network_ip,
                &config.network_prefix
            )) {
                Ok(tun) => Arc::new(tun),
                Err(e) => {
                    stop_tx.send(e).unwrap();
                    return;
                }
            };
            
            set_ipv4_forwarding(true).unwrap();
            
            for worker_id in 1..=4 {
                let handle = rt.handle().clone();
                let tun = tun.clone();
                let stop_tx = stop_tx.clone();
                let sessions = sessions.clone();
                let clients = clients.clone();
                thread::spawn(move || {
                    handle.block_on(async {
                        println!("Поток {} запущен", worker_id);
                        worker::create(
                            config.server_addr,
                            tun,
                            stop_tx,
                            sessions,
                            clients,
                            worker_id
                        ).await.unwrap();
                        println!("Поток {} завершен", worker_id);
                    });
                });
            }

            rt.block_on(async move {
                loop {
                    if let Some(error) = stop_rx.recv().await.ok() {
                        error!("Stopping the Lunestra runtime");
                        error!("{}", error);
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        });
    }
}

impl Stop for LunestraRunner {
    fn stop(runtime: &Configurable<Self>) {
        if let Some(tx) = runtime.runtime.stop_tx.clone() {
            tx.send(RuntimeError::StopSignal).unwrap();
        } else {
            error!("Runtime has not yet been launched");
        }
    }
}

pub type Lunestra = Configurable<LunestraRunner>;

impl Lunestra {
    pub fn new() -> Self {
        Self {
            config: None,
            runtime: LunestraRunner {
                stop_tx: None
            }
        }
    }
}
