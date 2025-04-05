mod error;
mod worker;
mod tun;

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin
};
use std::sync::Arc;
use std::time::Duration;
use self::{
    error::RuntimeError,
};

use tokio::sync::{broadcast, mpsc};
use tracing::{error, warn};
use shared::{
    credential::Credential,
    session::Alg
};
use crate::network::DefaultGateway;

pub struct Runtime {
    sock: SocketAddr,
    alg: Alg,
    cred: Credential,
    handshake_timeout: Duration,
    keepalive: Option<Duration>
}

impl Runtime {
    pub fn new(
        addr: IpAddr, 
        port: u16, 
        alg: Alg, 
        cred: Credential, 
        handshake_timeout: Duration, 
        keepalive: Option<Duration>
    ) -> Self {
        Self {
            sock: SocketAddr::new(addr, port),
            alg,
            cred,
            handshake_timeout,
            keepalive
        }
    }

    pub async fn run(&self) -> Result<(), RuntimeError> {
        tracing::info!("Connecting to udp://{}", self.sock);

        let (stop_tx, mut stop_rx) = broadcast::channel::<RuntimeError>(10);
        
        let worker = worker::create(
            self.sock,
            stop_tx,
            self.cred.clone(),
            self.alg.clone(),
            self.handshake_timeout,
            self.keepalive.clone()
        );
        
        tokio::select! {
            resp = worker => match resp {
                Ok(_) => {
                    warn!("worker stopped without error, waiting for stop signal");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(())
                },
                Err(err) => {
                    let msg = format!("worker result with unexpected error: {err}");
                    error!(msg);
                    Err(RuntimeError::Unexpected(err.to_string()))
                }
            },
            err = stop_rx.recv() => return match err {
                Ok(err) => Err(err),
                Err(err) => {
                    let msg = format!("stop channel is closed: {err}");
                    error!(msg);
                    Err(RuntimeError::Unexpected(msg))
                }
            }
        }
    }
}