pub mod error;
mod worker;
mod tun;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use self::{
    error::RuntimeError,
};

use tokio::sync::broadcast;
use tracing::{error, warn};
use shared::session::Alg;
use shared::connection_config::{CredentialsConfig, RuntimeConfig};

pub struct Runtime {
    sock: SocketAddr,
    alg: Alg,
    cred: CredentialsConfig,
    config: RuntimeConfig,
    pub stop_tx: broadcast::Sender<RuntimeError>
}

impl Runtime {
    pub fn new(
        addr: IpAddr,
        port: u16,
        alg: Alg,
        cred: CredentialsConfig,
        config: RuntimeConfig
    ) -> Self {
        let (stop_tx, _) = broadcast::channel::<RuntimeError>(10);
        Self {
            sock: SocketAddr::new(addr, port),
            alg,
            cred,
            config,
            stop_tx
        }
    }

    pub async fn run(&self) -> Result<(), RuntimeError> {
        tracing::info!("Connecting to udp://{}", self.sock);
        
        let worker = worker::create(
            self.sock,
            self.stop_tx.clone(),
            self.cred.clone(),
            self.alg.clone(),
            self.config.clone()
        );
        
        let mut stop_rx = self.stop_tx.subscribe();
        
        tokio::select! {
            resp = worker => match resp {
                Ok(_) => {
                    warn!("worker stopped without error, waiting for stop signal");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(())
                },
                Err(err) => {
                    error!("worker result with error");
                    Err(err)
                }
            },
            err = stop_rx.recv() => match err {
                Ok(err) => Err(err),
                Err(err) => {
                    Err(RuntimeError::IO(format!("stop channel is closed: {err}")))
                }
            }
        }
    }
}