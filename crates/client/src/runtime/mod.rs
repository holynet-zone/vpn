pub mod error;
mod worker;
mod transport;
pub mod state;

use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use self::{
    error::RuntimeError,
};

use tokio::sync::watch;
use tracing::debug;
use tun_rs::AsyncDevice;
use shared::session::Alg;
use shared::connection_config::{CredentialsConfig, RuntimeConfig};
use crate::runtime::state::RuntimeState;

pub struct Runtime {
    sock: SocketAddr,
    alg: Alg,
    cred: CredentialsConfig,
    config: RuntimeConfig,
    tun: Arc<AsyncDevice>,
    pub state_tx: watch::Sender<RuntimeState>
}

impl Runtime {
    pub fn new(
        sock: SocketAddr,
        tun: Arc<AsyncDevice>,
        alg: Alg,
        cred: CredentialsConfig,
        config: RuntimeConfig,
    ) -> Self {
        let (tx, _) = watch::channel(RuntimeState::Connecting);
        Self {
            sock,
            tun,
            alg,
            cred,
            config,
            state_tx: tx,
        }
    }

    pub async fn run(&self) -> Result<(), RuntimeError> {
        let worker = worker::create(
            self.sock,
            self.tun.clone(),
            self.state_tx.clone(),
            self.cred.clone(),
            self.alg.clone(),
            self.config.clone(),
        );

        let mut state_rx = self.state_tx.subscribe();
        
        tokio::select! {
            resp = worker => match resp {
                Ok(_) => {
                    debug!("worker stopped without error, try get err from state_tx");
                    match self.state_tx.borrow().deref() {
                        RuntimeState::Error(err) => Err(err.clone()),
                        _ => unreachable!("program closed without error")
                    }
                },
                Err(err) => {
                    debug!("worker result with error");
                    Err(err)
                }
            },
            state = state_rx.wait_for(|val| matches!(val, RuntimeState::Error(_))) => match state {
                Ok(state) => match state.deref() {
                    RuntimeState::Error(err) => Err(err.clone()),
                    _ => unreachable!("expected RuntimeState::Error(_), got {err:?}", err = state)
                },
                Err(err) => {
                    debug!("state channel broken");
                    Err(RuntimeError::IO(format!("state channel err: {err}")))
                }
            }
        }
    }
}