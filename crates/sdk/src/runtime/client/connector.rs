use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, error};

use crate::gateway::transport::ClientTransport;
use crate::protocol::Alg;
use crate::runtime::cred::Cred;
use crate::runtime::error::RuntimeError;
use crate::runtime::handshake::handshake_step;
use crate::runtime::state::{ClientSession, RuntimeState};

pub(crate) async fn executor<T: ClientTransport>(
    state: watch::Sender<RuntimeState>,
    transport: Arc<T>,
    cred: Cred,
    alg: Alg,
    reconnect_delay: Duration,
    timeout: Duration,
) {
    let mut state_rx = state.subscribe();
    state_rx.mark_changed();
    let mut ticker = tokio::time::interval(reconnect_delay);
    let mut is_reconnect = false;

    loop {
        match state_rx.changed().await {
            Ok(_) => {
                let current = state_rx.borrow().clone();
                match current {
                    RuntimeState::Connecting => match transport.connect().await {
                        Ok(_) => {
                            match handshake_step(transport.clone(), &cred, &alg, timeout).await {
                                Ok((payload, transport_state)) => {
                                    is_reconnect = true;
                                    state
                                        .send(RuntimeState::Connected((
                                            payload,
                                            ClientSession::new(transport_state),
                                        )))
                                        .expect("broken runtime state pipe");
                                    continue;
                                }
                                Err(err) => match is_reconnect {
                                    false => {
                                        state
                                            .send(RuntimeState::Error(err))
                                            .expect("broken runtime state pipe");
                                        return;
                                    }
                                    true => {
                                        error!("{}, trying again in {:?}", err, reconnect_delay);
                                        state_rx.mark_changed();
                                        ticker.tick().await;
                                    }
                                },
                            }
                        }
                        Err(err) => match is_reconnect {
                            false => {
                                state
                                    .send(RuntimeState::Error(RuntimeError::IO(format!(
                                        "connecting error: {}",
                                        err
                                    ))))
                                    .expect("broken runtime state pipe");
                                return;
                            }
                            true => {
                                error!(
                                    "failed to reconnect: {}, trying again in {:?}",
                                    err, reconnect_delay
                                );
                                state_rx.mark_changed();
                                ticker.tick().await;
                            }
                        },
                    },
                    RuntimeState::Error(_) => {
                        debug!("connector executor stopped by error state");
                        break;
                    }
                    _ => {}
                }
            }
            Err(err) => {
                debug!("state_rx channel error in connector executor: {}", err);
                break;
            }
        }
    }
}
